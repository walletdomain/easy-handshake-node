package handshake.node.chain;

import handshake.node.crypto.Blake2b;
import handshake.node.storage.ChainDB;
import handshake.node.storage.IndexStore;
import handshake.node.util.HexUtil;

import java.util.*;

/**
 * Cross-checks the indexes against the UTXO set and the stored blocks. Works in fixed-size pages, so memory use
 * does not depend on chain size. Any discrepancy is collected (first 50) and written to a diagnostic file.
 */
public final class IndexVerifier {
    private IndexVerifier() {}
    private static final int PAGE = 5000;

    public static final class Report {
        public long addrCoins, utxos, txEntries, sampledBlocks, problems;
        public final List<String> lines = new ArrayList<>();
        void problem(String s) { problems++; if (lines.size() < 50) lines.add(s); }
        public boolean ok() { return problems == 0; }
        @Override public String toString() {
            return "addrcoin=" + addrCoins + " utxos=" + utxos + " txindex=" + txEntries
                    + " sampledBlocks=" + sampledBlocks + " problems=" + problems;
        }
    }

    /** @param expectedTxs total transactions in the chain, or -1 if unknown; @param sampleStep check every Nth block's entries (0 = none) */
    public static Report verify(ChainDB db, long expectedTxs, int sampleStep) {
        Report r = new Report();
        IndexStore idx = db.index();
        if (idx == null) { r.problem("this database has no index maps"); return r; }
        boolean addr = db.addressIndexEnabled();

        // A: every address coin must be an unspent coin of that address
        if (addr) {
            byte[] from = null;
            while (true) {
                var page = idx.map(IndexStore.MAP_COIN).scanRange(from, null, PAGE, false);
                if (page.isEmpty()) break;
                for (var e : page) {
                    byte[] k = e.getKey();
                    r.addrCoins++;
                    int ver = k[0] & 0xFF, len = k[1] & 0xFF;
                    byte[] hash = Arrays.copyOfRange(k, 2, 2 + len);
                    byte[] txid = Arrays.copyOfRange(k, 2 + len, 34 + len);
                    int ix = ((k[34 + len] & 0xFF) << 24) | ((k[35 + len] & 0xFF) << 16) | ((k[36 + len] & 0xFF) << 8) | (k[37 + len] & 0xFF);
                    ChainDB.UtxoEntry u = db.getUtxo(HexUtil.encode(txid), ix);
                    if (u == null) r.problem("addrcoin entry without a UTXO: addr v" + ver + ":" + HexUtil.encode(hash) + " coin " + HexUtil.encode(txid) + ":" + ix);
                    else if (u.addrVersion() != ver || !Arrays.equals(u.addrHash(), hash))
                        r.problem("addrcoin entry has the wrong address: indexed v" + ver + ":" + HexUtil.encode(hash)
                                + " but the coin " + HexUtil.encode(txid) + ":" + ix + " belongs to v" + u.addrVersion() + ":" + HexUtil.encode(u.addrHash()));
                }
                from = Arrays.copyOf(page.get(page.size() - 1).getKey(), page.get(page.size() - 1).getKey().length + 1);
            }

            // B: every unspent coin must have its address coin entry
            from = null;
            while (true) {
                var page = db.utxoPage(from, PAGE);
                if (page.isEmpty()) break;
                for (var e : page) {
                    byte[] k = e.getKey();
                    r.utxos++;
                    ChainDB.UtxoEntry u = ChainDB.UtxoEntry.fromStorage(e.getValue());
                    if (u.addrVersion() == 31) continue;
                    byte[] txid = Arrays.copyOfRange(k, 0, 32);
                    int ix = ((k[32] & 0xFF) << 24) | ((k[33] & 0xFF) << 16) | ((k[34] & 0xFF) << 8) | (k[35] & 0xFF);
                    if (!idx.hasCoin(u.addrVersion(), u.addrHash(), txid, ix))
                        r.problem("UTXO without an addrcoin entry: " + HexUtil.encode(txid) + ":" + ix
                                + " addr v" + u.addrVersion() + ":" + HexUtil.encode(u.addrHash()) + " value " + u.value() + " height " + u.height());
                }
                from = Arrays.copyOf(page.get(page.size() - 1).getKey(), page.get(page.size() - 1).getKey().length + 1);
            }
        }

        // C: tx index size
        {
            byte[] from = null;
            while (true) {
                var page = idx.map(IndexStore.MAP_TX).scanRange(from, null, PAGE * 4, false);
                if (page.isEmpty()) break;
                r.txEntries += page.size();
                from = Arrays.copyOf(page.get(page.size() - 1).getKey(), 33);
            }
            if (expectedTxs >= 0 && r.txEntries != expectedTxs)
                r.problem("txindex has " + r.txEntries + " entries but the chain has " + expectedTxs + " transactions");
        }

        // D: sampled blocks -- tx locations and history entries
        if (sampleStep > 0) {
            int tip = Math.min(db.getBlockTip(), db.getIndexHeight());
            for (int h = 1; h <= tip; h += sampleStep) {
                byte[] raw = db.getBlock(h);
                if (raw == null) { r.problem("block " + h + " missing from the block store"); continue; }
                r.sampledBlocks++;
                List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(raw);
                for (int pos = 0; pos < txs.size(); pos++) {
                    TxParser.ParsedTx tx = txs.get(pos);
                    byte[] txid = Blake2b.hash256(Arrays.copyOf(tx.raw, tx.baseSize));
                    IndexStore.TxLoc loc = idx.txLocation(txid);
                    if (loc == null || loc.height() != h || loc.pos() != pos)
                        r.problem("txindex for " + HexUtil.encode(txid) + " is " + loc + ", expected height " + h + " pos " + pos);
                    if (!addr) continue;
                    for (int i = 0; i < tx.outputs.size(); i++) {
                        TxParser.Output o = tx.outputs.get(i);
                        if (o.addrVersion != 31 && !idx.hasHist(o.addrVersion, o.addrHash, h, pos))
                            r.problem("addrtx missing for output " + i + " of " + HexUtil.encode(txid) + " (height " + h + ", pos " + pos + ")");
                    }
                    boolean cb = tx.inputs.isEmpty() || tx.inputs.get(0).isCoinbase();
                    if (!cb) for (TxParser.Input in : tx.inputs) {
                        TxParser.Output po = BlockIndexer.resolveOutput(db, in.prevHash, in.prevIndex);
                        if (po != null && po.addrVersion != 31 && !idx.hasHist(po.addrVersion, po.addrHash, h, pos))
                            r.problem("addrtx missing for the spend of " + in.prevTxid + ":" + in.prevIndex + " by " + HexUtil.encode(txid) + " (height " + h + ", pos " + pos + ")");
                    }
                }
            }
        }

        System.out.println("[IndexVerify] " + r);
        if (!r.ok()) {
            Map<String, Object> ctx = new LinkedHashMap<>();
            ctx.put("addrcoin entries", r.addrCoins); ctx.put("utxos", r.utxos);
            ctx.put("txindex entries", r.txEntries); ctx.put("expected txs", expectedTxs);
            ctx.put("sampled blocks", r.sampledBlocks); ctx.put("problems", r.problems);
            IndexDiagnostics.dump(db, "index verification found " + r.problems + " problem(s)", null, ctx, r.lines);
        }
        return r;
    }
}