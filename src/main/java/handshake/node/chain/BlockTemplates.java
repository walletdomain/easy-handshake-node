package handshake.node.chain;

import handshake.node.crypto.Blake2b;
import handshake.node.crypto.MerkleUtil;
import handshake.node.storage.ChainDB;
import handshake.node.util.HexUtil;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Mining support: the consensus rules a NEW block must satisfy (difficulty
 * retargeting, median-time-past, subsidy, coinbase layout), a block template
 * builder, and the checks applied to a block handed to us via submitblock.
 * <p>
 * Everything here is a port of hsd 8.0.0 (lib/blockchain/chain.js getTarget /
 * getSuitableBlock / retarget / verifyContext, lib/mining/template.js
 * createCoinbase / refresh, lib/protocol/consensus.js getReward) and was
 * cross-checked against hsd itself (see the BT harness): same coinbase bytes,
 * same merkle and witness roots, same retarget results.
 * <p>
 * Scope, stated plainly:
 *  - Templates contain ONLY the coinbase transaction (no mempool
 *    transactions). Empty blocks are fully valid; adding fee-paying
 *    transactions needs per-transaction fee/finality/name-limit accounting
 *    that this node does not have yet.
 *  - submitblock accepts blocks whose non-coinbase transactions are all in
 *    OUR mempool (already validated on entry), and no coinbase claims or
 *    airdrop proofs.
 *  - Note: this node has no chainwork column populated, so retargeting sums
 *    per-block work straight from header bits (identical result, a window of
 *    ~144 headers).
 */
public final class BlockTemplates {

    /** Network consensus parameters (mainnet; tests may substitute easier ones). */
    public record Params(BigInteger powLimit, int powBits, int halvingInterval) {
        public static final Params MAINNET = new Params(
                new BigInteger("0000000000ffff00000000000000000000000000000000000000000000000000", 16),
                0x1c00ffff,
                170000);
    }

    public static final int  BLOCKS_PER_DAY      = 144;
    public static final int  TARGET_SPACING      = 600;
    public static final int  MEDIAN_TIMESPAN     = 11;
    public static final long MAX_FUTURE_SECONDS  = 2L * 60 * 60;
    public static final int  MAX_BLOCK_SIZE      = 1_000_000;
    public static final int  MAX_RAW_BLOCK_SIZE  = 4_000_000;
    public static final int  MAX_BLOCK_WEIGHT    = 4_000_000;
    public static final long BASE_REWARD         = 2000L * 1_000_000L;
    public static final int  MAX_COINBASE_WITNESS = 1000;

    private static final BigInteger MAX_CHAINWORK = BigInteger.ONE.shiftLeft(256);
    private static final SecureRandom RNG = new SecureRandom();

    private BlockTemplates() {}

    // ── Subsidy ───────────────────────────────────────────────────────────────

    /** consensus.getReward(height, interval) */
    public static long subsidy(int height, int halvingInterval) {
        int halvings = height / halvingInterval;
        if (halvings >= 52) return 0;
        return BASE_REWARD >> halvings;
    }

    // ── Compact target encoding ───────────────────────────────────────────────

    /** consensus.toCompact */
    public static int toCompact(BigInteger num) {
        if (num.signum() == 0) return 0;
        int exponent = (num.abs().bitLength() + 7) / 8;
        long mantissa;
        if (exponent <= 3) {
            mantissa = num.abs().longValue() << (8 * (3 - exponent));
        } else {
            mantissa = num.abs().shiftRight(8 * (exponent - 3)).longValue();
        }
        if ((mantissa & 0x800000L) != 0) {
            mantissa >>= 8;
            exponent += 1;
        }
        int compact = (exponent << 24) | (int) mantissa;
        if (num.signum() < 0) compact |= 0x800000;
        return compact;
    }

    /** ChainEntry.getProof(): (1 << 256) / (target + 1) */
    public static BigInteger proof(int bits) {
        BigInteger target = HeaderUtil.targetFromBits(bits);
        if (target.signum() <= 0) return BigInteger.ZERO;
        return MAX_CHAINWORK.divide(target.add(BigInteger.ONE));
    }

    // ── Median time past / difficulty ─────────────────────────────────────────

    private static byte[] headerAt(java.util.function.IntFunction<byte[]> hs, int height) {
        byte[] h = hs.apply(height);
        if (h == null) throw new IllegalStateException("missing header at height " + height);
        return h;
    }

    /** Median of the last 11 header timestamps ending at prevHeight (chain.getMedianTime). */
    public static long medianTimePast(java.util.function.IntFunction<byte[]> db, int prevHeight) {
        List<Long> times = new ArrayList<>();
        for (int i = 0, h = prevHeight; i < MEDIAN_TIMESPAN && h >= 0; i++, h--) {
            times.add(HeaderUtil.time(headerAt(db, h)));
        }
        java.util.Collections.sort(times);
        return times.get(times.size() >>> 1);
    }

    /** chain.getSuitableBlock: median-by-time of {h-2, h-1, h}; returns its height. */
    static int suitableBlock(java.util.function.IntFunction<byte[]> db, int h) {
        int zh = h, yh = h - 1, xh = h - 2;
        long zt = HeaderUtil.time(headerAt(db, zh));
        long yt = HeaderUtil.time(headerAt(db, yh));
        long xt = HeaderUtil.time(headerAt(db, xh));
        int t;
        long tt;
        if (xt > zt) { t = xh; xh = zh; zh = t; tt = xt; xt = zt; zt = tt; }
        if (xt > yt) { t = xh; xh = yh; yh = t; tt = xt; xt = yt; yt = tt; }
        if (yt > zt) { t = yh; yh = zh; zh = t; tt = yt; yt = zt; zt = tt; }
        return yh;
    }

    /**
     * The "bits" value the block AFTER prevHeight must carry (chain.getTarget
     * for mainnet: no testnet reset rule, retargeting enabled).
     */
    public static int expectedBits(java.util.function.IntFunction<byte[]> db, int prevHeight, Params p) {
        if (prevHeight < 0) return p.powBits();
        if (prevHeight < BLOCKS_PER_DAY + 2) return p.powBits();

        int lastH = suitableBlock(db, prevHeight);
        int ancestor = prevHeight - BLOCKS_PER_DAY;
        int firstH = suitableBlock(db, ancestor);
        return retarget(db, firstH, lastH, p);
    }

    /** chain.retarget(first, last), with chainwork differences summed from header bits. */
    static int retarget(java.util.function.IntFunction<byte[]> db, int firstH, int lastH, Params p) {
        long minActual = (long) (BLOCKS_PER_DAY / 4) * TARGET_SPACING;
        long maxActual = (long) (BLOCKS_PER_DAY * 4) * TARGET_SPACING;

        BigInteger work = BigInteger.ZERO;
        for (int h = firstH + 1; h <= lastH; h++) {
            work = work.add(proof(HeaderUtil.bits(headerAt(db, h))));
        }
        work = work.multiply(BigInteger.valueOf(TARGET_SPACING));

        long actual = HeaderUtil.time(headerAt(db, lastH)) - HeaderUtil.time(headerAt(db, firstH));
        if (actual < minActual) actual = minActual;
        if (actual > maxActual) actual = maxActual;

        work = work.divide(BigInteger.valueOf(actual));
        if (work.signum() == 0) return p.powBits();

        BigInteger target = MAX_CHAINWORK.divide(work).subtract(BigInteger.ONE);
        if (target.compareTo(p.powLimit()) > 0) return p.powBits();
        return toCompact(target);
    }

    // ChainDB convenience overloads (main-chain lookups).
    public static long medianTimePast(ChainDB db, int prevHeight) { return medianTimePast((java.util.function.IntFunction<byte[]>) db::getHeader, prevHeight); }
    static int suitableBlock(ChainDB db, int h) { return suitableBlock((java.util.function.IntFunction<byte[]>) db::getHeader, h); }
    public static int expectedBits(ChainDB db, int prevHeight, Params p) { return expectedBits((java.util.function.IntFunction<byte[]>) db::getHeader, prevHeight, p); }
    static int retarget(ChainDB db, int firstH, int lastH, Params p) { return retarget((java.util.function.IntFunction<byte[]>) db::getHeader, firstH, lastH, p); }

    // ── Coinbase ──────────────────────────────────────────────────────────────

    /** Result of building a coinbase: raw tx (with witness) plus its three hashes. */
    public static final class Coinbase {
        public final byte[] raw, txid, witnessHash;
        Coinbase(byte[] raw, byte[] txid, byte[] witnessHash) {
            this.raw = raw; this.txid = txid; this.witnessHash = witnessHash;
        }
    }

    /**
     * Builds the standard coinbase exactly as hsd's template.createCoinbase()
     * does: version 0, locktime = height, one null-prevout input with a random
     * sequence and a 3-item witness [coinbaseFlags, 8 random bytes, 8 zero
     * bytes], and one reward output with no covenant.
     */
    public static Coinbase buildCoinbase(int height, long value, int addrVersion,
                                         byte[] addrHash, byte[] coinbaseFlags) {
        if (coinbaseFlags == null) coinbaseFlags = new byte[0];
        ByteArrayOutputStream base = new ByteArrayOutputStream();
        writeLE32(base, 0);                       // tx version
        writeVarint(base, 1);                     // input count
        base.writeBytes(new byte[32]);            // prevout hash (null)
        writeLE32(base, 0xFFFFFFFF);              // prevout index (null)
        writeLE32(base, RNG.nextInt());           // sequence (random, as hsd)
        writeVarint(base, 1);                     // output count
        writeLE64(base, value);
        base.write(addrVersion);
        base.write(addrHash.length);
        base.writeBytes(addrHash);
        base.write(0);                            // covenant type NONE
        writeVarint(base, 0);                     // covenant items
        writeLE32(base, height);                  // locktime = height

        ByteArrayOutputStream wit = new ByteArrayOutputStream();
        writeVarint(wit, 3);
        writeVarint(wit, coinbaseFlags.length);
        wit.writeBytes(coinbaseFlags);
        byte[] extra = new byte[8];
        RNG.nextBytes(extra);
        writeVarint(wit, 8);
        wit.writeBytes(extra);
        writeVarint(wit, 8);
        wit.writeBytes(new byte[8]);

        byte[] baseBytes = base.toByteArray();
        byte[] witBytes = wit.toByteArray();
        if (witSize(coinbaseFlags.length) > MAX_COINBASE_WITNESS) {
            throw new IllegalArgumentException("coinbase flags too long");
        }
        byte[] raw = new byte[baseBytes.length + witBytes.length];
        System.arraycopy(baseBytes, 0, raw, 0, baseBytes.length);
        System.arraycopy(witBytes, 0, raw, baseBytes.length, witBytes.length);

        byte[] txid = Blake2b.hash256(baseBytes);
        byte[] wdhash = Blake2b.hash256(witBytes);
        byte[] wtxid = Blake2b.hash256(concat(txid, wdhash));
        return new Coinbase(raw, txid, wtxid);
    }

    private static int witSize(int flagsLen) {
        return varintSize(3) + varintSize(flagsLen) + flagsLen + (1 + 8) + (1 + 8);
    }

    // ── Template ──────────────────────────────────────────────────────────────

    public static final class Template {
        public final int height;
        public final byte[] prevHash, treeRoot, reservedRoot, merkleRoot, witnessRoot;
        public final int version, bits;
        public final long coinbaseValue, curTime, minTime, maxTime;
        public final Coinbase coinbase;

        Template(int height, byte[] prevHash, byte[] treeRoot, byte[] reservedRoot,
                 byte[] merkleRoot, byte[] witnessRoot, int version, int bits,
                 long coinbaseValue, long curTime, long minTime, long maxTime, Coinbase coinbase) {
            this.height = height; this.prevHash = prevHash; this.treeRoot = treeRoot;
            this.reservedRoot = reservedRoot; this.merkleRoot = merkleRoot;
            this.witnessRoot = witnessRoot; this.version = version; this.bits = bits;
            this.coinbaseValue = coinbaseValue; this.curTime = curTime; this.minTime = minTime;
            this.maxTime = maxTime; this.coinbase = coinbase;
        }

        /** The 236-byte header for the given miner-controlled fields. */
        public byte[] header(long nonce, long time, byte[] extraNonce24, byte[] mask32) {
            if (extraNonce24.length != 24 || mask32.length != 32)
                throw new IllegalArgumentException("extraNonce must be 24 bytes and mask 32");
            byte[] h = new byte[HeaderUtil.HEADER_SIZE];
            putLE32(h, HeaderUtil.OFF_NONCE, nonce);
            putLE64(h, HeaderUtil.OFF_TIME, time);
            System.arraycopy(prevHash, 0, h, HeaderUtil.OFF_PREVBLOCK, 32);
            System.arraycopy(treeRoot, 0, h, HeaderUtil.OFF_TREEROOT, 32);
            System.arraycopy(extraNonce24, 0, h, HeaderUtil.OFF_EXTRANONCE, 24);
            System.arraycopy(reservedRoot, 0, h, HeaderUtil.OFF_RESERVEDROOT, 32);
            System.arraycopy(witnessRoot, 0, h, HeaderUtil.OFF_WITNESSROOT, 32);
            System.arraycopy(merkleRoot, 0, h, HeaderUtil.OFF_MERKLEROOT, 32);
            putLE32(h, HeaderUtil.OFF_VERSION, version & 0xFFFFFFFFL);
            putLE32(h, HeaderUtil.OFF_BITS, bits & 0xFFFFFFFFL);
            System.arraycopy(mask32, 0, h, HeaderUtil.OFF_MASK, 32);
            return h;
        }

        /** The full serialized block (header + tx count + coinbase). */
        public byte[] block(long nonce, long time, byte[] extraNonce24, byte[] mask32) {
            byte[] h = header(nonce, time, extraNonce24, mask32);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.writeBytes(h);
            writeVarint(out, 1);
            out.writeBytes(coinbase.raw);
            return out.toByteArray();
        }
    }

    /**
     * Builds a coinbase-only template on top of the current block tip.
     * Preconditions (the caller reports them as RPC errors): the node's block
     * tip equals its header tip.
     */
    public static Template build(ChainDB db, int addrVersion, byte[] addrHash,
                                 byte[] coinbaseFlags, long nowSec, Params p) {
        int tipH = db.getBlockTip();
        byte[] tipHeader = headerAt((java.util.function.IntFunction<byte[]>) db::getHeader, tipH);
        int height = tipH + 1;
        long mtp = medianTimePast(db, tipH);
        long minTime = mtp + 1;
        long curTime = Math.max(nowSec, minTime);
        long reward = subsidy(height, p.halvingInterval());   // coinbase-only: no fees

        Coinbase cb = buildCoinbase(height, reward, addrVersion, addrHash, coinbaseFlags);
        byte[] merkle = MerkleUtil.buildRoot(List.of(cb.txid));
        byte[] witness = MerkleUtil.buildRoot(List.of(cb.witnessHash));
        byte[] treeRoot = db.getNameTree().committedRoot();

        return new Template(height, HeaderUtil.hash(tipHeader), treeRoot, new byte[32],
                merkle, witness, 0, expectedBits(db, tipH, p),
                reward, curTime, minTime, nowSec + MAX_FUTURE_SECONDS, cb);
    }

    // ── submitblock validation ────────────────────────────────────────────────

    /**
     * Validates a block handed to us for extension of OUR current tip.
     * Returns null if acceptable, otherwise a BIP22-style reason string.
     * Does not modify any state.
     */
    public static String checkBlock(ChainDB db, Mempool mempool, byte[] raw, long nowSec, Params p) {
        if (raw == null || raw.length < HeaderUtil.HEADER_SIZE + 1 || raw.length > MAX_RAW_BLOCK_SIZE)
            return "bad-blk-length";

        byte[] header = Arrays.copyOf(raw, HeaderUtil.HEADER_SIZE);
        byte[] hash = HeaderUtil.hash(header);

        int tipH = db.getBlockTip();
        if (tipH < 0 || db.getHeaderTip() != tipH) return "node-not-synced";

        int known = db.getHeightByHash(hash);
        if (known >= 0 && known <= db.getHeaderTip() && db.getHeader(known) != null) return "duplicate";

        byte[] tipHeader = headerAt((java.util.function.IntFunction<byte[]>) db::getHeader, tipH);
        byte[] prev = HeaderUtil.prevBlock(header);
        if (!Arrays.equals(prev, HeaderUtil.hash(tipHeader))) {
            int ph = db.getHeightByHash(prev);
            boolean prevKnown = ph >= 0 && ph <= tipH && db.getHeader(ph) != null;
            return prevKnown ? "inconclusive-not-best-prevblk" : "bad-prevblk";
        }
        int height = tipH + 1;

        if (!HeaderUtil.checkPOW(header)) return "high-hash";
        if (HeaderUtil.bits(header) != expectedBits(db, tipH, p)) return "bad-diffbits";

        long mtp = medianTimePast(db, tipH);
        long time = HeaderUtil.time(header);
        if (time <= mtp) return "time-too-old";
        if (time > nowSec + MAX_FUTURE_SECONDS) return "time-too-new";

        if (!Arrays.equals(HeaderUtil.treeRoot(header), db.getNameTree().committedRoot()))
            return "bad-treeroot";
        if (!Arrays.equals(HeaderUtil.reservedRoot(header), new byte[32]))
            return "bad-reservedroot";

        // ── transactions ──
        int pos = HeaderUtil.HEADER_SIZE;
        long count;
        int first = raw[pos] & 0xFF;
        if (first < 0xFD) { count = first; pos += 1; }
        else if (first == 0xFD) {
            if (pos + 3 > raw.length) return "bad-blk-length";
            count = (raw[pos + 1] & 0xFF) | ((raw[pos + 2] & 0xFF) << 8); pos += 3;
        } else return "bad-blk-length";
        if (count < 1) return "bad-blk-length";

        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(raw);
        if (txs.size() != count) return "bad-blk-parse";
        long used = pos, baseTotal = pos;
        for (TxParser.ParsedTx t : txs) { used += t.totalSize; baseTotal += t.baseSize; }
        if (used != raw.length) return "bad-blk-length";
        if (baseTotal > MAX_BLOCK_SIZE) return "bad-blk-length";
        if (baseTotal * 3 + raw.length > MAX_BLOCK_WEIGHT) return "bad-blk-weight";

        List<byte[]> txids = new ArrayList<>();
        List<byte[]> wtxids = new ArrayList<>();
        for (TxParser.ParsedTx t : txs) {
            byte[] txid = Blake2b.hash256(Arrays.copyOf(t.raw, t.baseSize));
            byte[] wd = Blake2b.hash256(Arrays.copyOfRange(t.raw, t.baseSize, t.totalSize));
            txids.add(txid);
            wtxids.add(Blake2b.hash256(concat(txid, wd)));
        }
        if (!Arrays.equals(MerkleUtil.buildRoot(txids), HeaderUtil.merkleRoot(header)))
            return "bad-txnmrklroot";
        if (!Arrays.equals(MerkleUtil.buildRoot(wtxids), HeaderUtil.witnessRoot(header)))
            return "bad-witnessroot";

        TxParser.ParsedTx cb = txs.get(0);
        if (cb.inputs.isEmpty() || !cb.inputs.get(0).isCoinbase()) return "bad-cb-missing";
        if (cb.inputs.size() != 1) return "unsupported-coinbase-claims";
        if ((cb.locktime & 0xFFFFFFFFL) != height) return "bad-cb-height";
        int cbWit = varintSize(cb.inputs.get(0).witness.size());
        for (byte[] item : cb.inputs.get(0).witness) cbWit += varintSize(item.length) + item.length;
        if (cbWit > MAX_COINBASE_WITNESS) return "bad-cb-length";
        long claimed = 0;
        for (TxParser.Output o : cb.outputs) {
            if (o.covenant != null && o.covenant.type != 0) return "unsupported-coinbase-covenant";
            if (o.value < 0) return "bad-txns-vout-negative";
            claimed += o.value;
        }
        if (cb.outputs.isEmpty()) return "bad-txns-vout-empty";

        long fees = 0;
        Set<String> seen = new HashSet<>();
        seen.add(HexUtil.encode(txids.get(0)));
        for (int i = 1; i < txs.size(); i++) {
            TxParser.ParsedTx t = txs.get(i);
            if (!t.inputs.isEmpty() && t.inputs.get(0).isCoinbase()) return "bad-cb-multiple";
            String id = HexUtil.encode(txids.get(i));
            if (!seen.add(id)) return "bad-txns-duplicate";
            Mempool.MempoolEntry e = mempool != null ? mempool.getEntry(id) : null;
            if (e == null) return "unvalidated-tx"; // only transactions our mempool already accepted
            if (!isFinal(t, height, mtp)) return "bad-txns-nonfinal";
            fees += e.fee;
        }
        if (claimed > subsidy(height, p.halvingInterval()) + fees) return "bad-cb-amount";
        return null;
    }

    /** primitives/tx.js isFinal(height, time) */
    static boolean isFinal(TxParser.ParsedTx tx, int height, long mtp) {
        long lock = tx.locktime & 0xFFFFFFFFL;
        if (lock == 0) return true;
        if ((lock & 0x80000000L) != 0) {
            if (((lock & 0x7FFFFFFFL) * 512L) < mtp) return true;
        } else {
            if (lock < height) return true;
        }
        for (TxParser.Input in : tx.inputs) {
            if ((in.sequence & 0xFFFFFFFFL) != 0xFFFFFFFFL) return false;
        }
        return true;
    }

    // ── Pure-Java CPU solver (tests, and the basis for the future miner) ──────

    /**
     * Scans nonces 0..maxNonce for a header satisfying its own target. Returns
     * the solved header or null. Only practical at test-level difficulty.
     */
    public static byte[] solve(Template t, long time, byte[] extraNonce24, byte[] mask32, long maxNonce) {
        for (long nonce = 0; nonce <= maxNonce; nonce++) {
            byte[] h = t.header(nonce, time, extraNonce24, mask32);
            if (HeaderUtil.checkPOW(h)) return h;
        }
        return null;
    }

    // ── Small encoders ────────────────────────────────────────────────────────

    static int varintSize(long n) {
        if (n < 0xFD) return 1;
        if (n <= 0xFFFF) return 3;
        if (n <= 0xFFFFFFFFL) return 5;
        return 9;
    }

    static void writeVarint(ByteArrayOutputStream o, long n) {
        if (n < 0xFD) { o.write((int) n); }
        else if (n <= 0xFFFF) { o.write(0xFD); o.write((int) (n & 0xFF)); o.write((int) ((n >> 8) & 0xFF)); }
        else { o.write(0xFE); writeLE32(o, (int) n); }
    }

    static void writeLE32(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF); o.write((v >>> 8) & 0xFF); o.write((v >>> 16) & 0xFF); o.write((v >>> 24) & 0xFF);
    }

    static void writeLE64(ByteArrayOutputStream o, long v) {
        for (int i = 0; i < 8; i++) o.write((int) ((v >>> (8 * i)) & 0xFF));
    }

    static void putLE32(byte[] b, int off, long v) {
        b[off] = (byte) v; b[off + 1] = (byte) (v >>> 8); b[off + 2] = (byte) (v >>> 16); b[off + 3] = (byte) (v >>> 24);
    }

    static void putLE64(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) b[off + i] = (byte) (v >>> (8 * i));
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }
}
