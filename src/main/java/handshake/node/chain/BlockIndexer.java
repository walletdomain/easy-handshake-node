package handshake.node.chain;

import handshake.node.crypto.Blake2b;
import handshake.node.storage.ChainDB;
import handshake.node.storage.IndexStore;
import handshake.node.util.HexUtil;

import java.util.*;

/**
 * Builds the tx / address indexes (see {@link IndexStore}) as blocks are connected, and repairs small gaps at
 * startup. Memory: a {@link Live} object holds one block's index entries and is dropped when the block is done;
 * nothing is cached across blocks.
 *
 * Failure policy: the chain is more important than the index. If anything goes wrong the index is suspended at the
 * last good height, a full diagnostic file is written, block processing carries on, and the next startup repairs the
 * gap automatically ({@link #catchUp}).
 */
public final class BlockIndexer {
    private BlockIndexer() {}

    private static boolean warnedSuspended = false;

    // ── live indexing ────────────────────────────────────────────────────────

    /** Returns the indexer for the block at {@code height}, or null when indexing is off or suspended. */
    public static Live begin(ChainDB db, int height) {
        IndexStore idx = db.index();
        if (idx == null) return null;
        int ih = db.getIndexHeight();
        boolean contiguous = ih >= height - 1 || (ih < 0 && height <= 1);
        if (!contiguous) {
            if (!warnedSuspended) {
                warnedSuspended = true;
                System.err.printf("[Index] Indexing is suspended: index is at height %d but block %d is being "
                        + "connected. It will be repaired automatically at the next startup.%n", ih, height);
            }
            return null;
        }
        return new Live(db, idx, height);
    }

    public static final class Live {
        private final ChainDB db;
        private final IndexStore idx;
        private final int height;
        private final boolean addr;
        private final IndexStore.Batch batch = new IndexStore.Batch();
        private final List<String> problems = new ArrayList<>();
        private int unresolved = 0, txCount = 0;
        private Throwable failure;
        private String where = "(start)";

        Live(ChainDB db, IndexStore idx, int height) {
            this.db = db; this.idx = idx; this.height = height; this.addr = db.addressIndexEnabled();
        }

        public void tx(int pos, byte[] txid) {
            if (failure != null) return;
            try { where = "tx " + pos + " " + HexUtil.encode(txid); batch.tx(txid, height, pos); txCount++; }
            catch (Throwable t) { failure = t; }
        }

        /** An input spent {@code coin} (null if the UTXO set no longer had it). */
        public void spent(int pos, byte[] txid, TxParser.Input in, ChainDB.UtxoEntry coin) {
            if (failure != null || !addr) return;
            try {
                where = "tx " + pos + " input " + in.prevTxid + ":" + in.prevIndex;
                int ver; byte[] hash;
                if (coin != null) { ver = coin.addrVersion(); hash = coin.addrHash(); }
                else {
                    TxParser.Output o = resolveOutput(db, in.prevHash, in.prevIndex);
                    if (o == null) {
                        unresolved++;
                        if (problems.size() < 50) problems.add("unresolved spent coin " + in.prevTxid + ":" + in.prevIndex
                                + " spent by tx " + pos + " (" + HexUtil.encode(txid) + ")");
                        return;
                    }
                    ver = o.addrVersion; hash = o.addrHash;
                }
                if (ver == 31) return;
                batch.hist(ver, hash, height, pos, txid);
                batch.coinRemove(ver, hash, in.prevHash, in.prevIndex);
            } catch (Throwable t) { failure = t; }
        }

        public void output(int pos, byte[] txid, int index, TxParser.Output out, boolean spendable) {
            if (failure != null || !addr) return;
            try {
                where = "tx " + pos + " output " + index;
                if (out.addrVersion == 31) return;
                batch.hist(out.addrVersion, out.addrHash, height, pos, txid);
                if (spendable) batch.coinAdd(out.addrVersion, out.addrHash, txid, index);
            } catch (Throwable t) { failure = t; }
        }

        /** Writes the block's entries and advances the index height; never throws. */
        public void finish() {
            try {
                if (failure != null) throw failure;
                if (unresolved > 0) {
                    // Not fatal: the index is still written, but this should never happen on a valid chain.
                    IndexDiagnostics.dump(db, unresolved + " spent coin(s) could not be resolved to an address at height " + height,
                            null, ctx(), problems);
                }
                idx.apply(batch, db.indexUndoSink());
                if (!addr && "1".equals(db.getMeta("addr_index_complete"))) db.putMeta("addr_index_complete", "0");
                else if (addr && db.getIndexHeight() < 0 && height <= 1) db.putMeta("addr_index_complete", "1");
                if (db.getIndexHeight() < height) db.setIndexHeight(height);
            } catch (Throwable t) {
                IndexDiagnostics.dump(db, "indexing block " + height + " failed; indexing suspended until next startup",
                        t, ctx(), problems);
            }
        }

        private Map<String, Object> ctx() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("height", height);
            m.put("last position", where);
            m.put("txs seen", txCount);
            m.put("batch entries", batch.size());
            m.put("unresolved spends", unresolved);
            return m;
        }
    }

    // ── fallback: find an output through the tx index ────────────────────────

    /** Finds output {@code index} of transaction {@code txid} by reading its block; null if unknown. Slow path. */
    public static TxParser.Output resolveOutput(ChainDB db, byte[] txid, int index) {
        IndexStore idx = db.index();
        if (idx == null) return null;
        IndexStore.TxLoc loc = idx.txLocation(txid);
        if (loc == null) return null;
        byte[] raw = db.getBlock(loc.height());
        if (raw == null) return null;
        List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(raw);
        if (loc.pos() >= txs.size()) return null;
        TxParser.ParsedTx t = txs.get(loc.pos());
        if (!Arrays.equals(Blake2b.hash256(Arrays.copyOf(t.raw, t.baseSize)), txid)) return null;
        return index >= 0 && index < t.outputs.size() ? t.outputs.get(index) : null;
    }

    // ── startup repair of a (small) gap ──────────────────────────────────────

    /**
     * Brings the index up to the block tip after a crash or an indexing failure (any gap size; the slow path is only used for the gap). Spent coins are resolved
     * through the tx index and an output only becomes an address coin if the UTXO set still holds it, so the result
     * is exactly the state at the tip.
     */
    public static boolean catchUp(ChainDB db) {
        IndexStore idx = db.index();
        if (idx == null) return true;
        int tip = db.getBlockTip();
        int from = db.getIndexHeight() + 1;
        if (tip < from) return true;
        System.out.printf("[Index] Repairing index: blocks %d..%d%n", from, tip);
        boolean addr = db.addressIndexEnabled();
        for (int h = Math.max(from, 1); h <= tip; h++) {
            String where = "(start)";
            List<String> problems = new ArrayList<>();
            try {
                byte[] raw = db.getBlock(h);
                if (raw == null) throw new IllegalStateException("block " + h + " is missing from the block store");
                List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(raw);
                IndexStore.Batch b = new IndexStore.Batch();
                for (int pos = 0; pos < txs.size(); pos++) {
                    TxParser.ParsedTx tx = txs.get(pos);
                    byte[] txid = Blake2b.hash256(Arrays.copyOf(tx.raw, tx.baseSize));
                    String txhex = HexUtil.encode(txid);
                    where = "tx " + pos + " " + txhex;
                    b.tx(txid, h, pos);
                    if (!addr) continue;
                    boolean cb = tx.inputs.isEmpty() || tx.inputs.get(0).isCoinbase();
                    if (!cb) for (TxParser.Input in : tx.inputs) {
                        TxParser.Output o = resolveOutput(db, in.prevHash, in.prevIndex);
                        if (o == null) { problems.add("unresolved spent coin " + in.prevTxid + ":" + in.prevIndex + " in tx " + pos); continue; }
                        if (o.addrVersion == 31) continue;
                        b.hist(o.addrVersion, o.addrHash, h, pos, txid);
                        b.coinRemove(o.addrVersion, o.addrHash, in.prevHash, in.prevIndex);
                    }
                    for (int i = 0; i < tx.outputs.size(); i++) {
                        TxParser.Output o = tx.outputs.get(i);
                        if (o.addrVersion == 31) continue;
                        b.hist(o.addrVersion, o.addrHash, h, pos, txid);
                        if (db.getUtxo(txhex, i) != null) b.coinAdd(o.addrVersion, o.addrHash, txid, i);
                    }
                }
                idx.apply(b, null);
                db.setIndexHeight(h);
                if (!problems.isEmpty())
                    IndexDiagnostics.dump(db, problems.size() + " unresolved spends while repairing block " + h, null,
                            Map.of("height", h), problems);
                if (h % 100 == 0) db.commit();
            } catch (Throwable t) {
                Map<String, Object> ctx = new LinkedHashMap<>();
                ctx.put("height", h); ctx.put("last position", where);
                IndexDiagnostics.dump(db, "index repair failed at block " + h, t, ctx, problems);
                db.commit();
                return false;
            }
        }
        db.commit();
        System.out.println("[Index] Index repaired up to height " + tip);
        return true;
    }
}