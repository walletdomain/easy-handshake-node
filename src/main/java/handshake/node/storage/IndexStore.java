package handshake.node.storage;

import java.util.*;

/**
 * The three block-derived indexes, each a RocksDB column family:
 *
 *   txindex   txid(32)                                   -> height(u32) pos(u32)
 *   addrtx    ver(1) len(1) hash  height(u32) pos(u32)   -> txid(32)       every tx that paid or spent from an address
 *   addrcoin  ver(1) len(1) hash  txid(32) index(u32)    -> (empty)        the address's currently unspent coins
 *
 * Design rules (learned the hard way with the Urkel tree):
 *  - NO in-memory caches of any kind: nothing here grows with chain size. A block's changes live in a
 *    short-lived {@link Batch} that is written once and dropped.
 *  - Every read is bounded: queries take a limit and a cursor and never materialize a whole map.
 *  - Writes are idempotent puts/deletes keyed by data from the block, so re-applying a block after a crash is
 *    harmless, and a reorg is undone from the pre-block values captured when the block was applied.
 */
public final class IndexStore {
    public static final int MAP_TX = 0, MAP_HIST = 1, MAP_COIN = 2;
    public static final String[] MAP_NAMES = { "txindex", "addrtx", "addrcoin" };
    /** Largest page any query returns, whatever the caller asks for. */
    public static final int MAX_PAGE = 1000;

    private final KVMap<byte[], byte[]> tx, hist, coin;

    IndexStore(KVStore store) {
        this.tx = store.openBytesBytesMap("txindex");
        this.hist = store.openBytesBytesMap("addrtx");
        this.coin = store.openBytesBytesMap("addrcoin");
    }

    public KVMap<byte[], byte[]> map(int which) { return which == MAP_TX ? tx : which == MAP_HIST ? hist : coin; }

    // ── key codecs ────────────────────────────────────────────────────────────

    static void putU32(byte[] b, int off, int v) {
        b[off] = (byte) (v >>> 24); b[off + 1] = (byte) (v >>> 16); b[off + 2] = (byte) (v >>> 8); b[off + 3] = (byte) v;
    }
    static int getU32(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    public static byte[] addrPrefix(int ver, byte[] hash) {
        byte[] p = new byte[2 + hash.length];
        p[0] = (byte) ver; p[1] = (byte) hash.length;
        System.arraycopy(hash, 0, p, 2, hash.length);
        return p;
    }
    public static byte[] histKey(int ver, byte[] hash, int height, int pos) {
        byte[] k = Arrays.copyOf(addrPrefix(ver, hash), 2 + hash.length + 8);
        putU32(k, 2 + hash.length, height); putU32(k, 6 + hash.length, pos);
        return k;
    }
    public static byte[] coinKey(int ver, byte[] hash, byte[] txid, int index) {
        byte[] k = Arrays.copyOf(addrPrefix(ver, hash), 2 + hash.length + 36);
        System.arraycopy(txid, 0, k, 2 + hash.length, 32); putU32(k, 34 + hash.length, index);
        return k;
    }
    public static byte[] txValue(int height, int pos) {
        byte[] v = new byte[8]; putU32(v, 0, height); putU32(v, 4, pos); return v;
    }
    private static byte[] prefixEnd(byte[] prefix) {      // > every key that starts with prefix (suffixes are <= 40 bytes)
        byte[] e = Arrays.copyOf(prefix, prefix.length + 40);
        Arrays.fill(e, prefix.length, e.length, (byte) 0xFF);
        return e;
    }
    private static byte[] after(byte[] key) { return Arrays.copyOf(key, key.length + 1); }   // smallest key > key

    // ── batch of one block's changes ──────────────────────────────────────────

    public static final class Batch {
        final List<Map.Entry<byte[], byte[]>> tx = new ArrayList<>(), hist = new ArrayList<>(), coin = new ArrayList<>();
        public void tx(byte[] txid, int height, int pos) { tx.add(Map.entry(txid, txValue(height, pos))); }
        public void hist(int ver, byte[] hash, int height, int pos, byte[] txid) {
            hist.add(Map.entry(histKey(ver, hash, height, pos), txid));
        }
        public void coinAdd(int ver, byte[] hash, byte[] txid, int index) {
            coin.add(Map.entry(coinKey(ver, hash, txid, index), new byte[0]));
        }
        public void coinRemove(int ver, byte[] hash, byte[] txid, int index) {
            coin.add(new AbstractMap.SimpleEntry<>(coinKey(ver, hash, txid, index), null));
        }
        public int size() { return tx.size() + hist.size() + coin.size(); }
        public List<Map.Entry<byte[], byte[]>> ops(int which) { return which == MAP_TX ? tx : which == MAP_HIST ? hist : coin; }
    }

    /**
     * Writes the batch. When {@code undoSink} is non-null, first records (mapId||key, previous value or null)
     * for every key the batch touches, so {@link #undo} can restore the pre-block state.
     */
    public void apply(Batch b, List<byte[][]> undoSink) {
        for (int w = 0; w < 3; w++) {
            List<Map.Entry<byte[], byte[]>> ops = b.ops(w);
            if (undoSink != null) {
                for (Map.Entry<byte[], byte[]> op : ops) {
                    byte[] k = op.getKey();
                    byte[] ck = new byte[k.length + 1];
                    ck[0] = (byte) w; System.arraycopy(k, 0, ck, 1, k.length);
                    undoSink.add(new byte[][] { ck, map(w).get(k) });
                }
            }
            map(w).applyOps(ops);
        }
    }

    /** Reverses recorded ops (given in recording order; applied last-to-first). */
    public void undo(List<byte[][]> ops) {
        for (int i = ops.size() - 1; i >= 0; i--) {
            byte[][] op = ops.get(i);
            int w = op[0][0];
            byte[] k = Arrays.copyOfRange(op[0], 1, op[0].length);
            if (op[1] == null) map(w).remove(k); else map(w).put(k, op[1]);
        }
    }

    // ── queries (always bounded) ──────────────────────────────────────────────

    public record TxLoc(int height, int pos) {}
    public record AddrTx(int height, int pos, byte[] txid) {}
    public record Outpoint(byte[] txid, int index) {}

    public TxLoc txLocation(byte[] txid) {
        byte[] v = tx.get(txid);
        return v == null || v.length != 8 ? null : new TxLoc(getU32(v, 0), getU32(v, 4));
    }

    /** Transactions touching an address, oldest first (or newest first when {@code reverse}); {@code after} is an exclusive cursor. */
    public List<AddrTx> addressTxs(int ver, byte[] hash, int limit, AddrTx after, boolean reverse) {
        limit = Math.max(1, Math.min(limit, MAX_PAGE));
        byte[] prefix = addrPrefix(ver, hash);
        byte[] from = prefix, to = prefixEnd(prefix);
        if (after != null) {
            byte[] ck = histKey(ver, hash, after.height(), after.pos());
            if (reverse) to = ck; else from = after(ck);
        }
        List<AddrTx> out = new ArrayList<>();
        for (Map.Entry<byte[], byte[]> e : hist.scanRange(from, to, limit, reverse)) {
            byte[] k = e.getKey();
            out.add(new AddrTx(getU32(k, k.length - 8), getU32(k, k.length - 4), e.getValue()));
        }
        return out;
    }

    /** Currently unspent coins of an address, ordered by txid; {@code after} is an exclusive cursor. */
    public List<Outpoint> addressCoins(int ver, byte[] hash, int limit, Outpoint after) {
        limit = Math.max(1, Math.min(limit, MAX_PAGE));
        byte[] prefix = addrPrefix(ver, hash);
        byte[] from = after == null ? prefix : after(coinKey(ver, hash, after.txid(), after.index()));
        List<Outpoint> out = new ArrayList<>();
        for (Map.Entry<byte[], byte[]> e : coin.scanRange(from, prefixEnd(prefix), limit, false)) {
            byte[] k = e.getKey();
            out.add(new Outpoint(Arrays.copyOfRange(k, k.length - 36, k.length - 4), getU32(k, k.length - 4)));
        }
        return out;
    }

    public boolean hasCoin(int ver, byte[] hash, byte[] txid, int index) {
        return coin.containsKey(coinKey(ver, hash, txid, index));
    }
    public boolean hasHist(int ver, byte[] hash, int height, int pos) {
        return hist.containsKey(histKey(ver, hash, height, pos));
    }

    public void clearAll() { for (int w = 0; w < 3; w++) map(w).clearFast(); }

    public String stats() {
        StringBuilder sb = new StringBuilder();
        for (int w = 0; w < 3; w++) sb.append(MAP_NAMES[w]).append('[').append(map(w).stats()).append("] ");
        return sb.toString().trim();
    }
}