package handshake.node.server;

import handshake.node.NodeConfig;
import handshake.node.chain.BlockTemplates;
import handshake.node.chain.ChainSync;
import handshake.node.chain.HeaderUtil;
import handshake.node.chain.Mempool;
import handshake.node.crypto.Bech32;
import handshake.node.crypto.Blake2b;
import handshake.node.server.RpcServer.RpcException;
import handshake.node.storage.ChainDB;
import handshake.node.util.HexUtil;
import handshake.node.util.NodeClock;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The mining side of the RPC interface, behaving like hsd's lib/node/rpc.js: getwork / getworklp / submitwork,
 * getmininginfo, getnetworkhashps, getgenerate / setgenerate / generate / generatetoaddress, plus the template
 * bookkeeping they share.
 * <p>
 * Work model (same as hsd): one current block template built for the configured reward address
 * ({@code miner.address}); the last 10 templates are remembered by witness root so late submissions of recent
 * work are still recognised; a new tip (or a changed mempool, at most every 10 s) retires the current template.
 * Submitted work is rebuilt into a full block and handed to the same path as {@code submitblock}, so it gets the
 * identical full validation.
 * <p>
 * Differences from hsd, on purpose: the long-poll waits at most {@link #LONGPOLL_MAX_MS} and then returns fresh
 * work (a client that holds an HTTP request open forever is not something this node needs), at most
 * {@link #MAX_POLLERS} long-polls run at once, and {@code generate}/{@code generatetoaddress} stop after
 * {@link #GENERATE_MAX_MS} per block (on mainnet difficulty they cannot finish; they exist for test networks).
 */
public final class MiningService implements RpcServer.BlockListener {

    static final long LONGPOLL_MAX_MS = 5 * 60_000L;
    static final int  MAX_POLLERS = 8;
    static final long GENERATE_MAX_MS = 10 * 60_000L;
    static final int  MAX_TEMPLATES = 10;
    /** hsd: a changed mempool only refreshes the template if the last refresh is older than this. */
    static final long TX_REFRESH_MS = 10_000L;

    private final NodeConfig config;
    private final ChainDB db;
    private final ChainSync sync;
    private final Mempool mempool;
    private static final SecureRandom RNG = new SecureRandom();

    // ── current work (guarded by this) ──
    private BlockTemplates.Template attempt;
    private long attemptAt;
    private int attemptPoolSig;
    private final LinkedHashMap<String, BlockTemplates.Template> byWitnessRoot = new LinkedHashMap<>();
    private final AtomicInteger pollers = new AtomicInteger();

    // ── CPU mining (setgenerate) ──
    private volatile boolean generating;
    private volatile int procLimit;
    private Thread cpuThread;

    public MiningService(NodeConfig config, ChainDB db, ChainSync sync, Mempool mempool) {
        this.config = config;
        this.db = db;
        this.sync = sync;
        this.mempool = mempool;
    }

    // ── block notifications: a new or removed block retires the current template ──

    @Override public void onNewBlock(int height, byte[] hash, byte[] rawBlock) { refresh(); }
    @Override public void onBlockDisconnected(int height, byte[] hash, byte[] rawBlock) { refresh(); }

    synchronized void refresh() {
        attempt = null;
        byWitnessRoot.clear();
    }

    // ── helpers ──

    private BlockTemplates.Params powParams() { return sync.getPowParams(); }

    /** The configured reward address as {version, hash}, or an RPC error if none. */
    private Object[] rewardAddress(String override) throws RpcException {
        String addr = override != null ? override : config.getMinerAddress();
        if (addr == null || addr.isBlank())
            throw new RpcException(-1, "No addresses available for coinbase.");
        return decodeAddress(addr);
    }

    static Object[] decodeAddress(String addr) throws RpcException {
        try {
            Object[] d = Bech32.decode(addr);
            int version = (int) d[1];
            byte[] hash = (byte[]) d[2];
            if (!"hs".equals(d[0])) throw new RpcException(-5, "Not a mainnet (hs1...) address");
            if (version != 0 || (hash.length != 20 && hash.length != 32))
                throw new RpcException(-5, "Unsupported reward address type");
            return new Object[]{version, hash};
        } catch (RpcException e) {
            throw e;
        } catch (Exception e) {
            throw new RpcException(-5, "Invalid address");
        }
    }

    private int poolSignature() {
        int sig = 0;
        if (mempool == null) return 0;
        for (Mempool.MempoolEntry e : mempool.getAll()) sig += e.txid.hashCode() * 31 + 1;
        return sig;
    }

    /** True if the node can build work on its current tip. */
    private void requireReadyChain() throws RpcException {
        int tipH = db.getBlockTip();
        if (tipH < 0 || db.getHeaderTip() != tipH) throw new RpcException(-10, "Node is still syncing");
    }

    /** hsd updateWork(): the current template, building a new one if needed. */
    synchronized BlockTemplates.Template updateWork() throws RpcException {
        long now = System.currentTimeMillis();
        if (attempt != null && now - attemptAt > TX_REFRESH_MS && poolSignature() != attemptPoolSig) refresh();
        if (attempt != null) return attempt;

        Object[] a = rewardAddress(null);
        requireReadyChain();
        byte[] flags = config.getMinerCoinbaseFlags().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        BlockTemplates.Template t;
        try {
            t = BlockTemplates.build(db, mempool, (int) a[0], (byte[]) a[1], flags, now / 1000, powParams());
        } catch (Exception e) {
            throw new RpcException(-1, "Could not build template: " + e.getMessage());
        }
        if (byWitnessRoot.size() >= MAX_TEMPLATES) {
            String oldest = byWitnessRoot.keySet().iterator().next();
            byWitnessRoot.remove(oldest);
        }
        attempt = t;
        attemptAt = now;
        attemptPoolSig = poolSignature();
        byWitnessRoot.put(HexUtil.encode(t.witnessRoot), t);
        return t;
    }

    static byte[] targetBytes(int bits) {
        byte[] target = new byte[32];
        byte[] tb = HeaderUtil.targetFromBits(bits).toByteArray();
        for (int i = 0; i < tb.length && i < 32; i++) target[31 - i] = tb[tb.length - 1 - i];
        return target;
    }

    // ── miner header format (hsd Headers.toMiner / fromMiner), 256 bytes ──

    /**
     * nonce(4) time(8) padding(20) prevBlock(32) treeRoot(32) maskHash(32) extraNonce(24) reservedRoot(32)
     * witnessRoot(32) merkleRoot(32) version(4) bits(4), where padding[i] = prevBlock[i] ^ treeRoot[i] and
     * maskHash = blake2b(prevBlock || mask).
     */
    public static byte[] toMiner(byte[] header236) {
        byte[] out = new byte[256];
        System.arraycopy(header236, HeaderUtil.OFF_NONCE, out, 0, 4);
        System.arraycopy(header236, HeaderUtil.OFF_TIME, out, 4, 8);
        byte[] prev = HeaderUtil.prevBlock(header236), tree = HeaderUtil.treeRoot(header236);
        for (int i = 0; i < 20; i++) out[12 + i] = (byte) (prev[i % 32] ^ tree[i % 32]);
        System.arraycopy(prev, 0, out, 32, 32);
        System.arraycopy(tree, 0, out, 64, 32);
        byte[] pm = new byte[64];
        System.arraycopy(prev, 0, pm, 0, 32);
        System.arraycopy(HeaderUtil.mask(header236), 0, pm, 32, 32);
        System.arraycopy(Blake2b.hash256(pm), 0, out, 96, 32);
        System.arraycopy(HeaderUtil.extraNonce(header236), 0, out, 128, 24);
        System.arraycopy(HeaderUtil.reservedRoot(header236), 0, out, 152, 32);
        System.arraycopy(HeaderUtil.witnessRoot(header236), 0, out, 184, 32);
        System.arraycopy(HeaderUtil.merkleRoot(header236), 0, out, 216, 32);
        System.arraycopy(header236, HeaderUtil.OFF_VERSION, out, 248, 4);
        System.arraycopy(header236, HeaderUtil.OFF_BITS, out, 252, 4);
        return out;
    }

    // ── getwork / getworklp ──

    public String getWork() throws RpcException {
        BlockTemplates.Template t = updateWork();
        long now = NodeClock.nowSec();
        long time = Math.max(now, t.minTime);
        byte[] data = toMiner(t.header(0, time, new byte[24], new byte[32]));
        return "{\"network\":\"" + networkType() + "\","
                + "\"data\":\"" + HexUtil.encode(data) + "\","
                + "\"target\":\"" + HexUtil.encode(targetBytes(t.bits)) + "\","
                + "\"height\":" + t.height + ","
                + "\"time\":" + now + ","
                + "\"fee\":" + t.fees + "}";
    }

    public String getWorkLongpoll() throws RpcException {
        awaitChange(null);
        return getWork();
    }

    String networkType() { return "main"; }

    /**
     * Blocks until the chain tip changes, a new template is needed because the mempool changed (at most every
     * 10 s, like hsd), or the long-poll limit passes. {@code watchedTip} null means "the tip as of now".
     */
    void awaitChange(byte[] watchedTip) throws RpcException {
        if (pollers.incrementAndGet() > MAX_POLLERS) {
            pollers.decrementAndGet();
            throw new RpcException(-9, "Too many long polls in progress.");
        }
        try {
            int tipH = db.getBlockTip();
            byte[] tipHeader = db.getHeader(tipH);
            byte[] startTip = watchedTip != null ? watchedTip : (tipHeader == null ? new byte[32] : HeaderUtil.hash(tipHeader));
            int startSig;
            long startAt;
            synchronized (this) { startSig = attempt != null ? attemptPoolSig : poolSignature(); startAt = attempt != null ? attemptAt : System.currentTimeMillis(); }
            long deadline = System.currentTimeMillis() + LONGPOLL_MAX_MS;
            while (System.currentTimeMillis() < deadline) {
                try { Thread.sleep(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                int h = db.getBlockTip();
                byte[] th = db.getHeader(h);
                if (th != null && !Arrays.equals(HeaderUtil.hash(th), startTip)) return;
                if (System.currentTimeMillis() - startAt > TX_REFRESH_MS && poolSignature() != startSig) return;
            }
        } finally {
            pollers.decrementAndGet();
        }
    }

    // ── submitwork ──

    /** hsd handleWork: returns {@code [true,"valid"]} or {@code [false,reason]}. */
    public String submitWork(byte[] data, byte[] mask) throws RpcException {
        if (data.length != 256) return "[false,\"invalid-data-length\"]";
        byte[] nonceB = Arrays.copyOfRange(data, 0, 4);
        byte[] timeB = Arrays.copyOfRange(data, 4, 12);
        byte[] padding = Arrays.copyOfRange(data, 12, 32);
        byte[] prev = Arrays.copyOfRange(data, 32, 64);
        byte[] tree = Arrays.copyOfRange(data, 64, 96);
        byte[] maskHash = Arrays.copyOfRange(data, 96, 128);
        byte[] extra = Arrays.copyOfRange(data, 128, 152);
        byte[] reserved = Arrays.copyOfRange(data, 152, 184);
        byte[] witness = Arrays.copyOfRange(data, 184, 216);
        for (int i = 0; i < 20; i++)
            if (padding[i] != (byte) (prev[i % 32] ^ tree[i % 32])) throw new RpcException(-1, "Invalid work data.");

        byte[] pm = new byte[64];
        System.arraycopy(prev, 0, pm, 0, 32);
        System.arraycopy(mask, 0, pm, 32, 32);
        if (!Arrays.equals(Blake2b.hash256(pm), maskHash)) return "[false,\"bad-maskhash\"]";

        BlockTemplates.Template t;
        synchronized (this) { t = byWitnessRoot.get(HexUtil.encode(witness)); }
        if (t == null) return "[false,\"stale\"]";
        int version = (int) le32(data, 248), bits = (int) le32(data, 252);
        if (!Arrays.equals(prev, t.prevHash) || bits != t.bits) return "[false,\"stale\"]";

        long nonce = le32(data, 0);
        long time = 0;
        for (int i = 7; i >= 0; i--) time = (time << 8) | (timeB[i] & 0xFFL);
        if (!Arrays.equals(tree, t.treeRoot) || !Arrays.equals(reserved, t.reservedRoot)
                || !Arrays.equals(Arrays.copyOfRange(data, 216, 248), t.merkleRoot) || version != t.version)
            return "[false,\"stale\"]";

        byte[] header = t.header(nonce, time, extra, mask);
        if (!HeaderUtil.checkPOW(header)) return "[false,\"bad-diffbits\"]";

        byte[] block = t.block(nonce, time, extra, mask);
        String reason = sync.submitBlock(block);
        if (reason != null) return "[false,\"" + RpcServer.escape(reason) + "\"]";
        refresh();
        return "[true,\"valid\"]";
    }

    private static long le32(byte[] b, int o) {
        return (b[o] & 0xFFL) | ((b[o + 1] & 0xFFL) << 8) | ((b[o + 2] & 0xFFL) << 16) | ((b[o + 3] & 0xFFL) << 24);
    }

    // ── getmininginfo / getnetworkhashps ──

    public String getMiningInfo(RpcServer rpc) {
        BlockTemplates.Template t;
        synchronized (this) { t = attempt; }
        long size = 0;
        int weight = 0, txs = 0;
        double diff = 0;
        if (t != null) {
            txs = t.txs.size() + 1;
            weight = t.weight;
            diff = RpcServer.difficultyOf(t.bits);
            size = 1000;
            for (BlockTemplates.Included i : t.txs) size += i.raw.length;
        }
        String hps;
        try { hps = RpcServer.number(getHashRate(120, -1)); } catch (RpcException e) { hps = "0"; }
        return "{\"blocks\":" + db.getBlockTip()
                + ",\"currentblocksize\":" + size
                + ",\"currentblockweight\":" + weight
                + ",\"currentblocktx\":" + txs
                + ",\"difficulty\":" + RpcServer.number(diff)
                + ",\"errors\":\"\""
                + ",\"genproclimit\":" + procLimit
                + ",\"networkhashps\":" + hps
                + ",\"pooledtx\":" + (mempool == null ? 0 : mempool.size())
                + ",\"testnet\":" + !"main".equals(handshake.node.chain.BlockProcessor.params.type)
                + ",\"chain\":\"" + handshake.node.chain.BlockProcessor.params.type + "\""
                + ",\"generate\":" + generating + "}";
    }

    /**
     * hsd getHashRate(lookup, height): total work of the last {@code lookup} blocks divided by the time span of
     * the lookup+1 headers ending at the tip (or at {@code height}). 0 if the span is 0.
     */
    public double getHashRate(int lookup, int height) throws RpcException {
        int tip = height >= 0 ? height : db.getBlockTip();
        if (tip < 0 || db.getHeader(tip) == null) return 0;
        if (lookup == 0) lookup = tip % 144 + 1;
        if (lookup > tip) lookup = tip;
        long min = HeaderUtil.time(db.getHeader(tip)), max = min;
        BigInteger work = BigInteger.ZERO;
        for (int i = 0; i < lookup; i++) {
            byte[] hdr = db.getHeader(tip - i);
            work = work.add(BlockTemplates.proof(HeaderUtil.bits(hdr)));
            byte[] prev = db.getHeader(tip - i - 1);
            if (prev == null) throw new RpcException(-20, "Not found.");
            long ptime = HeaderUtil.time(prev);
            min = Math.min(ptime, min);
            max = Math.max(ptime, max);
        }
        long diff = max - min;
        if (diff == 0) return 0;
        return work.doubleValue() / diff;
    }

    // ── generate / setgenerate ──

    public boolean isGenerating() { return generating; }

    /** Tries to mine one block on the current tip for {@code addr}; returns its hash hex or null on time-out/stale. */
    private String mineOne(Object[] addr, long maxTries, long deadlineMs) throws RpcException {
        requireReadyChain();
        byte[] flags = config.getMinerCoinbaseFlags().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        long tries = 0;
        while (System.currentTimeMillis() < deadlineMs) {
            long now = NodeClock.nowSec();
            BlockTemplates.Template t = BlockTemplates.build(db, mempool, (int) addr[0], (byte[]) addr[1], flags, now, powParams());
            byte[] extra = new byte[24];
            RNG.nextBytes(extra);
            long time = Math.max(now, t.minTime);
            byte[] zeroMask = new byte[32];
            final long chunk = 1L << 16;
            for (long n = 0; n < (1L << 32); n += chunk) {
                if (cpuThread != null && Thread.currentThread() == cpuThread && !generating) return null;
                if (System.currentTimeMillis() >= deadlineMs) return null;
                if (db.getBlockTip() + 1 != t.height) break; // tip moved: build a new template
                long last = Math.min(n + chunk - 1, (1L << 32) - 1);
                if (maxTries > 0) last = Math.min(last, n + (maxTries - tries) - 1);
                for (long nonce = n; nonce <= last; nonce++) {
                    byte[] h = t.header(nonce, time, extra, zeroMask);
                    if (!HeaderUtil.checkPOW(h)) continue;
                    byte[] block = t.block(nonce, time, extra, zeroMask);
                    String err = sync.submitBlock(block);
                    if (err == null) { refresh(); return HexUtil.encode(HeaderUtil.hash(h)); }
                    throw new RpcException(-1, "Mined block was rejected: " + err);
                }
                tries += (last - n + 1);
                if (maxTries > 0 && tries >= maxTries) return null;
            }
        }
        return null;
    }

    public String generate(int blocks, String addressOverride, long maxTries) throws RpcException {
        Object[] addr = rewardAddress(addressOverride);
        List<String> hashes = new ArrayList<>();
        for (int i = 0; i < blocks; i++) {
            String h = mineOne(addr, maxTries, System.currentTimeMillis() + GENERATE_MAX_MS);
            if (h == null) throw new RpcException(-1, "No block found within the allowed tries/time (" + hashes.size() + " of " + blocks + " mined).");
            hashes.add(h);
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < hashes.size(); i++) { if (i > 0) sb.append(','); sb.append('"').append(hashes.get(i)).append('"'); }
        return sb.append(']').toString();
    }

    public synchronized String setGenerate(boolean mine, int limit) throws RpcException {
        procLimit = limit;
        if (mine) {
            Object[] addr = rewardAddress(null);
            if (generating) return "true";
            generating = true;
            cpuThread = new Thread(() -> {
                while (generating) {
                    try {
                        mineOne(addr, 0, Long.MAX_VALUE);
                    } catch (RpcException e) {
                        try { Thread.sleep(5000); } catch (InterruptedException ie) { return; }
                    } catch (Exception e) {
                        System.err.println("[Mining] CPU miner error: " + e);
                        try { Thread.sleep(5000); } catch (InterruptedException ie) { return; }
                    }
                }
            }, "cpu-miner");
            cpuThread.setDaemon(true);
            cpuThread.start();
            return "true";
        }
        generating = false;
        return "false";
    }
}