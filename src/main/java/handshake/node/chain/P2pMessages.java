package handshake.node.chain;

import handshake.node.crypto.Blake2b;
import handshake.node.crypto.SipHash;
import handshake.node.urkeltree.UrkelBits;
import handshake.node.urkeltree.UrkelProof;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Pure (connection-free) encoders/decoders for the hsd P2P packets that ChainSync serves:
 * GETBLOCKS, INV, NOTFOUND, FEEFILTER, SENDCMPCT, CMPCTBLOCK, GETBLOCKTXN, BLOCKTXN, GETPROOF, PROOF.
 * Every layout here was taken from hsd's lib/net/packets.js, lib/net/bip152.js and urkel's proof.js, and is
 * checked byte-for-byte against hsd in the differential tests.
 * <p>
 * Malformed input never throws out of the parse methods that take peer data: they throw
 * {@link MalformedPacket}, which the caller turns into a log line (and a ban where hsd bans).
 */
public final class P2pMessages {
    private P2pMessages() {}

    // hsd packet type numbers (lib/net/packets.js exports.types)
    public static final int MSG_FEEFILTER   = 21;
    public static final int MSG_SENDCMPCT   = 22;
    public static final int MSG_CMPCTBLOCK  = 23;
    public static final int MSG_GETBLOCKTXN = 24;
    public static final int MSG_BLOCKTXN    = 25;
    public static final int MSG_GETPROOF    = 26;
    public static final int MSG_PROOF       = 27;
    public static final int MSG_CLAIM       = 28;
    public static final int MSG_AIRDROP     = 29;

    // inv item types (lib/primitives/invitem.js)
    public static final int INV_TX = 1, INV_BLOCK = 2, INV_FILTERED_BLOCK = 3, INV_CMPCT_BLOCK = 4,
            INV_CLAIM = 5, INV_AIRDROP = 6;

    /** hsd common.MAX_INV */
    public static final int MAX_INV = 50_000;
    /** hsd serves at most this many hashes per getblocks reply. */
    public static final int GETBLOCKS_LIMIT = 500;
    /** hsd flushes inv in chunks of this many items. */
    public static final int INV_CHUNK = 1000;
    /** consensus.MAX_MONEY: 2.04e9 * 1e6 dollarydoos */
    public static final long MAX_MONEY = 2_040_000_000_000_000L;

    public static final class MalformedPacket extends Exception {
        public MalformedPacket(String m) { super(m); }
    }

    // ── varint helpers (Bitcoin-style, as bufio) ─────────────────────────────

    /** Reads a varint at pos[0] and advances it. */
    static long readVarint(byte[] b, int[] pos) throws MalformedPacket {
        int p = pos[0];
        if (p >= b.length) throw new MalformedPacket("varint past end");
        int first = b[p] & 0xFF;
        long v;
        int len;
        if (first < 0xFD) { v = first; len = 1; }
        else if (first == 0xFD) { need(b, p, 3); v = (b[p + 1] & 0xFF) | ((b[p + 2] & 0xFF) << 8); len = 3;
            if (v < 0xFD) throw new MalformedPacket("non-canonical varint"); }
        else if (first == 0xFE) { need(b, p, 5); v = u32(b, p + 1); len = 5;
            if (v < 0x10000L) throw new MalformedPacket("non-canonical varint"); }
        else { need(b, p, 9); v = u32(b, p + 1) | (u32(b, p + 5) << 32); len = 9;
            if (v < 0x100000000L || v < 0) throw new MalformedPacket("non-canonical/oversized varint"); }
        pos[0] = p + len;
        return v;
    }

    static void writeVarint(ByteArrayOutputStream o, long v) {
        if (v < 0xFD) o.write((int) v);
        else if (v <= 0xFFFF) { o.write(0xFD); o.write((int) v); o.write((int) (v >>> 8)); }
        else if (v <= 0xFFFFFFFFL) { o.write(0xFE); le32(o, v); }
        else { o.write(0xFF); le32(o, v); le32(o, v >>> 32); }
    }

    static long u32(byte[] b, int o) {
        return (b[o] & 0xFFL) | ((b[o + 1] & 0xFFL) << 8) | ((b[o + 2] & 0xFFL) << 16) | ((b[o + 3] & 0xFFL) << 24);
    }

    static void le32(ByteArrayOutputStream o, long v) {
        o.write((int) v); o.write((int) (v >>> 8)); o.write((int) (v >>> 16)); o.write((int) (v >>> 24));
    }

    private static void need(byte[] b, int p, int n) throws MalformedPacket {
        if (p + n > b.length) throw new MalformedPacket("truncated");
    }

    // ── GETBLOCKS / GETHEADERS ───────────────────────────────────────────────

    public static final class Locator {
        public final List<byte[]> hashes;
        public final byte[] stop;
        Locator(List<byte[]> h, byte[] s) { hashes = h; stop = s; }
    }

    /** payload: varint count, count x 32-byte hash, 32-byte stop. Count is capped at MAX_INV like hsd. */
    public static Locator parseLocator(byte[] payload) throws MalformedPacket {
        int[] pos = {0};
        long count = readVarint(payload, pos);
        if (count > MAX_INV) throw new MalformedPacket("too many block hashes (" + count + ")");
        if (pos[0] + count * 32 + 32 != payload.length)
            throw new MalformedPacket("bad getblocks length " + payload.length + " for " + count + " hashes");
        List<byte[]> hashes = new ArrayList<>((int) count);
        for (int i = 0; i < count; i++) {
            hashes.add(Arrays.copyOfRange(payload, pos[0], pos[0] + 32));
            pos[0] += 32;
        }
        return new Locator(hashes, Arrays.copyOfRange(payload, pos[0], pos[0] + 32));
    }

    public static byte[] encodeLocator(List<byte[]> hashes, byte[] stop) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        writeVarint(o, hashes.size());
        for (byte[] h : hashes) o.write(h, 0, 32);
        o.write(stop == null ? new byte[32] : stop, 0, 32);
        return o.toByteArray();
    }

    // ── INV / GETDATA / NOTFOUND item lists ──────────────────────────────────

    public static final class Item {
        public final int type; public final byte[] hash;
        public Item(int type, byte[] hash) { this.type = type; this.hash = hash; }
    }

    /** payload: varint count, count x (u32 type + 32-byte hash). The count cap is the caller's business. */
    public static List<Item> parseItems(byte[] payload) throws MalformedPacket {
        int[] pos = {0};
        long count = readVarint(payload, pos);
        if (count > MAX_INV) throw new MalformedPacket("too many items (" + count + ")");
        if (pos[0] + count * 36 > payload.length) throw new MalformedPacket("truncated item list");
        List<Item> items = new ArrayList<>((int) count);
        for (int i = 0; i < count; i++) {
            items.add(new Item((int) u32(payload, pos[0]), Arrays.copyOfRange(payload, pos[0] + 4, pos[0] + 36)));
            pos[0] += 36;
        }
        return items;
    }

    public static byte[] encodeItems(List<Item> items) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(1 + items.size() * 36);
        writeVarint(o, items.size());
        for (Item it : items) { le32(o, it.type); o.write(it.hash, 0, 32); }
        return o.toByteArray();
    }

    // ── FEEFILTER / SENDCMPCT ────────────────────────────────────────────────

    /** payload: i64 LE rate (dollarydoos per kB). Returns the raw signed value. */
    public static long parseFeeFilter(byte[] p) throws MalformedPacket {
        if (p.length != 8) throw new MalformedPacket("bad feefilter length " + p.length);
        return u32(p, 0) | (u32(p, 4) << 32);
    }

    public static byte[] encodeFeeFilter(long rate) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(8);
        le32(o, rate); le32(o, rate >>> 32);
        return o.toByteArray();
    }

    /** payload: u8 mode, u64 version. Returns {mode, version}; a version that does not fit an int is clamped. */
    public static long[] parseSendCmpct(byte[] p) throws MalformedPacket {
        if (p.length != 9) throw new MalformedPacket("bad sendcmpct length " + p.length);
        long hi = u32(p, 5);
        long ver = hi != 0 ? Long.MAX_VALUE : u32(p, 1);
        return new long[]{p[0] & 0xFF, ver};
    }

    public static byte[] encodeSendCmpct(int mode, long version) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(9);
        o.write(mode); le32(o, version); le32(o, version >>> 32);
        return o.toByteArray();
    }

    // ── compact blocks (BIP152 as implemented in hsd lib/net/bip152.js) ──────

    /** wtxid = blake2b(txid || blake2b(witness bytes)), the same value the block's witnessRoot is built from. */
    public static byte[] wtxid(TxParser.ParsedTx t) {
        byte[] txid = Blake2b.hash256(Arrays.copyOf(t.raw, t.baseSize));
        byte[] wd = Blake2b.hash256(Arrays.copyOfRange(t.raw, t.baseSize, t.totalSize));
        byte[] both = new byte[64];
        System.arraycopy(txid, 0, both, 0, 32);
        System.arraycopy(wd, 0, both, 32, 32);
        return Blake2b.hash256(both);
    }

    /** SipHash key = blake2b-256(header || keyNonce)[0..16] */
    static byte[] sipKey(byte[] header, byte[] keyNonce) {
        byte[] in = new byte[header.length + keyNonce.length];
        System.arraycopy(header, 0, in, 0, header.length);
        System.arraycopy(keyNonce, 0, in, header.length, keyNonce.length);
        return Arrays.copyOf(Blake2b.hash256(in), 16);
    }

    /** 48-bit short id: low 48 bits of siphash24(wtxid). */
    static long shortId(byte[] sipKey, byte[] wtxid) {
        return SipHash.hash24(sipKey, wtxid) & 0xFFFFFFFFFFFFL;
    }

    /**
     * CMPCTBLOCK payload for a raw block: header(236) || keyNonce(8) || varint(idCount) || ids (u32 lo, u16 hi) ||
     * varint(1) || varint(0) || coinbase tx. Same layout hsd's CompactBlock.fromBlock produces.
     *
     * @return null if the block cannot be parsed
     */
    public static byte[] buildCompactBlock(byte[] rawBlock, byte[] keyNonce) {
        if (keyNonce == null || keyNonce.length != 8) throw new IllegalArgumentException("keyNonce must be 8 bytes");
        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
        if (txs.isEmpty() || txs.size() > 0xFFFF) return null;
        byte[] header = Arrays.copyOf(rawBlock, HeaderUtil.HEADER_SIZE);
        byte[] key = sipKey(header, keyNonce);
        ByteArrayOutputStream o = new ByteArrayOutputStream(rawBlock.length / 4 + 512);
        o.write(header, 0, header.length);
        o.write(keyNonce, 0, 8);
        writeVarint(o, txs.size() - 1);
        for (int i = 1; i < txs.size(); i++) {
            long id = shortId(key, wtxid(txs.get(i)));
            le32(o, id & 0xFFFFFFFFL);
            o.write((int) (id >>> 32)); o.write((int) (id >>> 40));
        }
        writeVarint(o, 1);
        writeVarint(o, 0);
        byte[] cb = txs.get(0).raw;
        o.write(cb, 0, cb.length);
        return o.toByteArray();
    }

    /** GETBLOCKTXN payload: hash(32) || varint count || differentially-encoded indexes. */
    public static final class TxRequest {
        public final byte[] hash; public final int[] indexes;
        TxRequest(byte[] h, int[] i) { hash = h; indexes = i; }
    }

    public static TxRequest parseGetBlockTxn(byte[] p) throws MalformedPacket {
        if (p.length < 33) throw new MalformedPacket("truncated getblocktxn");
        byte[] hash = Arrays.copyOf(p, 32);
        int[] pos = {32};
        long count = readVarint(p, pos);
        if (count > 0x10000 || count > p.length) throw new MalformedPacket("too many indexes (" + count + ")");
        int[] idx = new int[(int) count];
        long offset = 0;
        for (int i = 0; i < count; i++) {
            long d = readVarint(p, pos);
            long index = d + offset;
            if (d > 0xFFFF || index > 0xFFFF) throw new MalformedPacket("index too large");
            idx[i] = (int) index;
            offset = index + 1;
        }
        if (pos[0] != p.length) throw new MalformedPacket("trailing bytes in getblocktxn");
        return new TxRequest(hash, idx);
    }

    public static byte[] encodeGetBlockTxn(byte[] hash, int[] indexes) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(hash, 0, 32);
        writeVarint(o, indexes.length);
        for (int i = 0; i < indexes.length; i++) writeVarint(o, i == 0 ? indexes[0] : indexes[i] - (indexes[i - 1] + 1));
        return o.toByteArray();
    }

    /**
     * BLOCKTXN payload: hash(32) || varint count || txs, for the requested indexes. Like hsd, stops at the first
     * index that is out of range rather than failing.
     */
    public static byte[] buildBlockTxn(byte[] rawBlock, TxRequest req) {
        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int n = 0;
        for (int index : req.indexes) {
            if (index >= txs.size()) break;
            byte[] raw = txs.get(index).raw;
            body.write(raw, 0, raw.length);
            n++;
        }
        ByteArrayOutputStream o = new ByteArrayOutputStream(40 + body.size());
        o.write(req.hash, 0, 32);
        writeVarint(o, n);
        byte[] b = body.toByteArray();
        o.write(b, 0, b.length);
        return o.toByteArray();
    }

    // ── GETPROOF / PROOF (urkel proof wire format, 256-bit keys, blake2b) ────

    /** GETPROOF payload: root(32) || key(32). */
    public static byte[][] parseGetProof(byte[] p) throws MalformedPacket {
        if (p.length != 64) throw new MalformedPacket("bad getproof length " + p.length);
        return new byte[][]{Arrays.copyOf(p, 32), Arrays.copyOfRange(p, 32, 64)};
    }

    public static byte[] encodeGetProof(byte[] root, byte[] key) {
        byte[] o = new byte[64];
        System.arraycopy(root, 0, o, 0, 32);
        System.arraycopy(key, 0, o, 32, 32);
        return o;
    }

    /** PROOF payload: root(32) || key(32) || urkel proof. */
    public static byte[] encodeProofPacket(byte[] root, byte[] key, UrkelProof proof) {
        byte[] pr = encodeProof(proof);
        byte[] o = new byte[64 + pr.length];
        System.arraycopy(root, 0, o, 0, 32);
        System.arraycopy(key, 0, o, 32, 32);
        System.arraycopy(pr, 0, o, 64, pr.length);
        return o;
    }

    /**
     * urkel Proof.encode(blake2b, 256): u16 LE (type &lt;&lt; 14 | depth), u16 LE node count, a bitfield (one bit per
     * node, MSB first) flagging nodes with a non-empty prefix, then per node [prefix][32-byte hash], then the
     * type-specific tail.
     */
    public static byte[] encodeProof(UrkelProof pr) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        int field = (pr.type << 14) | pr.depth;
        o.write(field); o.write(field >>> 8);
        int count = pr.nodes.size();
        o.write(count); o.write(count >>> 8);
        byte[] bits = new byte[(count + 7) >>> 3];
        for (int i = 0; i < count; i++) if (pr.nodes.get(i).prefix.size != 0) bits[i >>> 3] |= (byte) (0x80 >>> (i & 7));
        o.write(bits, 0, bits.length);
        for (UrkelProof.ProofNode n : pr.nodes) {
            if (n.prefix.size != 0) writeBits(o, n.prefix);
            o.write(n.hash, 0, 32);
        }
        switch (pr.type) {
            case UrkelProof.TYPE_DEADEND -> { }
            case UrkelProof.TYPE_SHORT -> {
                writeBits(o, pr.prefix);
                o.write(pr.left, 0, 32);
                o.write(pr.right, 0, 32);
            }
            case UrkelProof.TYPE_COLLISION -> {
                o.write(pr.key, 0, 32);
                o.write(pr.hash, 0, 32);
            }
            case UrkelProof.TYPE_EXISTS -> {
                o.write(pr.value.length); o.write(pr.value.length >>> 8);
                o.write(pr.value, 0, pr.value.length);
            }
            default -> throw new IllegalStateException("bad proof type " + pr.type);
        }
        return o.toByteArray();
    }

    private static void writeBits(ByteArrayOutputStream o, UrkelBits b) {
        if (b.size >= 0x80) o.write(0x80 | (b.size >>> 8));
        o.write(b.size);
        int bytes = (b.size + 7) >>> 3;
        o.write(b.data, 0, bytes);
    }

    /** Decodes a proof written by {@link #encodeProof} / urkel (for tests and for validating PROOF replies). */
    public static UrkelProof decodeProof(byte[] d, int off, int[] endOut) throws MalformedPacket {
        int[] pos = {off};
        UrkelProof pr = new UrkelProof();
        need(d, pos[0], 4);
        int field = (d[pos[0]] & 0xFF) | ((d[pos[0] + 1] & 0xFF) << 8);
        pr.type = field >>> 14;
        pr.depth = field & 0x3FFF;
        if (pr.depth > 256) throw new MalformedPacket("invalid proof depth");
        int count = (d[pos[0] + 2] & 0xFF) | ((d[pos[0] + 3] & 0xFF) << 8);
        if (count > 256) throw new MalformedPacket("proof too large");
        pos[0] += 4;
        int bsize = (count + 7) >>> 3;
        need(d, pos[0], bsize);
        int bitsAt = pos[0];
        pos[0] += bsize;
        for (int i = 0; i < count; i++) {
            UrkelBits prefix = UrkelBits.EMPTY;
            if ((d[bitsAt + (i >>> 3)] & (0x80 >>> (i & 7))) != 0) {
                prefix = readBits(d, pos);
                if (prefix.size == 0 || prefix.size > 256) throw new MalformedPacket("invalid prefix size");
            }
            need(d, pos[0], 32);
            pr.push(prefix, Arrays.copyOfRange(d, pos[0], pos[0] + 32));
            pos[0] += 32;
        }
        switch (pr.type) {
            case UrkelProof.TYPE_DEADEND -> { }
            case UrkelProof.TYPE_SHORT -> {
                pr.prefix = readBits(d, pos);
                need(d, pos[0], 64);
                pr.left = Arrays.copyOfRange(d, pos[0], pos[0] + 32);
                pr.right = Arrays.copyOfRange(d, pos[0] + 32, pos[0] + 64);
                pos[0] += 64;
            }
            case UrkelProof.TYPE_COLLISION -> {
                need(d, pos[0], 64);
                pr.key = Arrays.copyOfRange(d, pos[0], pos[0] + 32);
                pr.hash = Arrays.copyOfRange(d, pos[0] + 32, pos[0] + 64);
                pos[0] += 64;
            }
            case UrkelProof.TYPE_EXISTS -> {
                need(d, pos[0], 2);
                int vl = (d[pos[0]] & 0xFF) | ((d[pos[0] + 1] & 0xFF) << 8);
                pos[0] += 2;
                need(d, pos[0], vl);
                pr.value = Arrays.copyOfRange(d, pos[0], pos[0] + vl);
                pos[0] += vl;
            }
            default -> throw new MalformedPacket("bad proof type");
        }
        if (endOut != null) endOut[0] = pos[0];
        return pr;
    }

    private static UrkelBits readBits(byte[] d, int[] pos) throws MalformedPacket {
        need(d, pos[0], 1);
        int size = d[pos[0]++] & 0xFF;
        if ((size & 0x80) != 0) {
            need(d, pos[0], 1);
            size = ((size - 0x80) << 8) + (d[pos[0]++] & 0xFF);
        }
        int bytes = (size + 7) >>> 3;
        need(d, pos[0], bytes);
        UrkelBits b = UrkelBits.alloc(size);
        System.arraycopy(d, pos[0], b.data, 0, bytes);
        pos[0] += bytes;
        return b;
    }
}