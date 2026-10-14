package handshake.node.chain;

import handshake.node.storage.ChainDB;
import handshake.node.util.HexUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Contextual validation of a block's transactions against the chain state,
 * ported from hsd's chain.verifyInputs() / verifyLocks() / verifyCovenants()
 * and tx.checkInputs(). It is READ-ONLY: spent and created coins and name
 * changes live in an in-memory overlay, so a block that fails halfway leaves
 * the database untouched (the caller applies the block only after this
 * returns success).
 *
 * Not verified (documented gaps): airdrop proofs and DNSSEC ownership proofs in
 * coinbase inputs. A block whose coinbase carries such proofs is reported via
 * {@link Result#coinbaseProofs} so the caller can decide (peer blocks: accept,
 * the proofs were already checked by the miners/PoW; submitblock: refuse).
 */
public final class BlockValidator {
    private BlockValidator() {}

    /** Chain state the validator reads. */
    public interface ChainCtx extends NameRules.MainChain {
        ChainDB.UtxoEntry utxo(String txid, int index);
        ChainDB.NameEntry name(byte[] nameHash);
        /** Median time past of the main-chain header at {@code height} (chain.getMedianTime). */
        long medianTimeAt(int height);
    }

    public static final class Result {
        public final ConsensusRules.Fail fail;       // null when valid
        public final long fees;
        public final boolean coinbaseProofs;
        public final int failedTx;                   // index of the offending tx, -1 if n/a
        /** On success: coins created / spent by the block ("txid:index" keys) and name states it changed. */
        public Map<String, ChainDB.UtxoEntry> created = Map.of();
        public Set<String> spent = Set.of();
        public Map<String, ChainDB.NameEntry> names = Map.of();
        Result(ConsensusRules.Fail fail, long fees, boolean coinbaseProofs, int failedTx) {
            this.fail = fail; this.fees = fees; this.coinbaseProofs = coinbaseProofs; this.failedTx = failedTx;
        }
        public boolean ok() { return fail == null; }
        @Override public String toString() {
            return fail == null ? "ok(fees=" + fees + ")" : fail.reason() + (failedTx >= 0 ? " (tx " + failedTx + ")" : "");
        }
    }

    static boolean unspendable(int addrVersion, int covenantType) {
        return addrVersion == 31 || covenantType == ConsensusRules.REVOKE;
    }

    private static final class Spend { final int tx, in; final ChainDB.UtxoEntry coin;
        Spend(int tx, int in, ChainDB.UtxoEntry coin) { this.tx = tx; this.in = in; this.coin = coin; } }

    /**
     * @param txs         every transaction of the block, coinbase first
     * @param txids       natural txid bytes for each tx
     * @param height      height of the block being validated
     * @param prevMtp     median time past of the previous block
     * @param scriptFlags HsScript verify flags (MANDATORY for blocks)
     * @param checkScripts false to skip script/signature execution
     * @param nameFlags   NameRules.FLAG_* deployment flags
     */
    public static Result validate(ChainCtx chain, ConsensusParams p, List<TxParser.ParsedTx> txs, List<byte[]> txids,
                                  int height, long prevMtp, int scriptFlags, boolean checkScripts, int nameFlags) {
        // ── structure ──
        if (txs.isEmpty() || !ConsensusRules.isCoinbase(txs.get(0))) return fail("bad-cb-missing", 100, 0);
        for (int i = 0; i < txs.size(); i++) {
            if (i > 0 && ConsensusRules.isCoinbase(txs.get(i))) return fail("bad-cb-multiple", 100, i);
            ConsensusRules.Fail f = ConsensusRules.checkSanity(txs.get(i));
            if (f != null) return new Result(f, 0, false, i);
        }
        // ── block-level name DoS limits (chain.verify) ──
        Set<String> nameSet = new HashSet<>();
        int opens = 0, updates = 0, renewals = 0;
        for (int i = 0; i < txs.size(); i++) {
            TxParser.ParsedTx tx = txs.get(i);
            opens += ConsensusRules.countOpens(tx);
            if (opens > ConsensusParams.MAX_BLOCK_OPENS) return fail("bad-blk-opens", 100, i);
            updates += ConsensusRules.countUpdates(tx);
            if (updates > ConsensusParams.MAX_BLOCK_UPDATES) return fail("bad-blk-updates", 100, i);
            renewals += ConsensusRules.countRenewals(tx);
            if (renewals > ConsensusParams.MAX_BLOCK_RENEWALS) return fail("bad-blk-renewals", 100, i);
            if (ConsensusRules.hasNames(tx, nameSet)) return fail("bad-blk-names", 100, i);
            ConsensusRules.addNames(tx, nameSet);
        }

        TxParser.ParsedTx cb = txs.get(0);
        if ((cb.locktime & 0xFFFFFFFFL) != height) return fail("bad-cb-height", 100, 0);
        boolean proofs = cb.inputs.size() > 1;
        for (int i = 1; i < cb.inputs.size(); i++) {
            if (cb.inputs.get(i).witness.size() != 1) return fail("bad-witness-size", 100, 0);
            if (i >= cb.outputs.size()) return fail("bad-output", 100, 0);
        }

        // ── overlay ──
        Map<String, ChainDB.UtxoEntry> created = new HashMap<>();
        Set<String> spent = new HashSet<>();
        NameRules.NameView names = new NameRules.NameView(chain::name);
        List<Spend> scriptJobs = new ArrayList<>();
        java.util.function.BiFunction<String, Integer, ChainDB.UtxoEntry> coinLookup = (t, ix) -> {
            String key = t + ":" + ix;
            if (spent.contains(key)) return null;
            ChainDB.UtxoEntry c = created.get(key);
            return c != null ? c : chain.utxo(t, ix);
        };

        St st = new St();
        st.created = created; st.spent = spent; st.names = names; st.scriptJobs = scriptJobs;
        st.coinLookup = coinLookup; st.maxSigops = ConsensusParams.MAX_BLOCK_SIGOPS;

        for (int i = 0; i < txs.size(); i++) {
            TxParser.ParsedTx tx = txs.get(i);
            String txid = HexUtil.encode(txids.get(i));
            boolean isCb = i == 0;

            if (!isCb) {
                ConsensusRules.Fail f = txChecks(st, chain, p, tx, txid, i, height, prevMtp, nameFlags);
                if (f != null) return new Result(f, 0, proofs, i);
            }

            if (isCb && proofs) {
                // CLAIM covenants in the coinbase change name state (their DNSSEC proofs are not verified here)
                ConsensusRules.Fail nf = NameRules.verify(tx, txid, names, height, nameFlags, p, chain, coinLookup);
                if (nf != null) return new Result(nf, 0, proofs, i);
            }

            // addTX
            for (int o = 0; o < tx.outputs.size(); o++) {
                TxParser.Output out = tx.outputs.get(o);
                if (unspendable(out.addrVersion, out.covenant.type)) continue;
                created.put(txid + ":" + o, new ChainDB.UtxoEntry(out.value, out.addrVersion, out.addrHash,
                        out.covenant.type, ConsensusRules.encodeCovenantItems(out.covenant), isCb, height));
            }
        }

        // block reward
        long reward = st.reward + p.subsidy(height);
        long claimed = 0;
        for (TxParser.Output o : cb.outputs) claimed += o.value;
        if (!proofs && claimed > reward) return fail("bad-cb-amount", 0, 0);

        // scripts
        if (checkScripts) {
            for (Spend s : scriptJobs) {
                TxParser.ParsedTx tx = txs.get(s.tx);
                if (!HsScript.verifyInput(tx, s.in, s.coin.addrVersion(), s.coin.addrHash(), s.coin.value(), scriptFlags))
                    return fail("mandatory-script-verify-flag-failed", 100, s.tx);
            }
        }

        long fees = reward - p.subsidy(height);
        Result res = new Result(null, fees, proofs, -1);
        res.created = created;
        res.spent = spent;
        res.names = names.changed();
        return res;
    }


    /** Mutable per-validation state shared by block and single-transaction validation. */
    private static final class St {
        Map<String, ChainDB.UtxoEntry> created;
        Set<String> spent;
        NameRules.NameView names;
        List<Spend> scriptJobs;
        java.util.function.BiFunction<String, Integer, ChainDB.UtxoEntry> coinLookup;
        long sigops, reward, maxSigops;
        long lastFee;
    }

    /** The non-coinbase part of hsd's chain.verifyInputs for one transaction (scripts are queued, not run). */
    private static ConsensusRules.Fail txChecks(St st, ChainCtx chain, ConsensusParams p, TxParser.ParsedTx tx,
                                                String txid, int i, int height, long prevMtp, int nameFlags) {
        Map<String, ChainDB.UtxoEntry> created = st.created;
        Set<String> spent = st.spent;
        if (!ConsensusRules.isFinal(tx, height, prevMtp)) return failF("bad-txns-nonfinal", 10, i);

        // spendInputs
        List<ChainDB.UtxoEntry> coins = new ArrayList<>(tx.inputs.size());
        for (TxParser.Input in : tx.inputs) {
            String key = HexUtil.encode(in.prevHash) + ":" + in.prevIndex;
            ChainDB.UtxoEntry coin = null;
            if (!spent.contains(key)) {
                coin = created.get(key);
                if (coin == null) coin = chain.utxo(HexUtil.encode(in.prevHash), in.prevIndex);
                if (coin != null && unspendable(coin.addrVersion(), coin.covenantType())) coin = null;
            }
            if (coin == null) return failF("bad-txns-inputs-missingorspent", 100, i);
            spent.add(key);
            coins.add(coin);
        }

        // verifyLocks (sequence locks)
        long minHeight = -1, minTime = -1;
        for (int k = 0; k < tx.inputs.size(); k++) {
            int seq = tx.inputs.get(k).sequence;
            if ((seq & 0x80000000) != 0) continue;
            int coinHeight = coins.get(k).height();
            long h = coinHeight;
            if ((seq & (1 << 22)) == 0) {
                h += (seq & 0xFFFF) - 1;
                minHeight = Math.max(minHeight, h);
                continue;
            }
            h = Math.max(h - 1, 0);
            long time = chain.medianTimeAt((int) h);
            time += ((long) (seq & 0xFFFF) << 9) - 1;
            minTime = Math.max(minTime, time);
        }
        if (minHeight != -1 && minHeight >= height) return failF("bad-txns-nonfinal", 100, i);
        if (minTime != -1 && minTime >= prevMtp) return failF("bad-txns-nonfinal", 100, i);

        // sigops
        for (int k = 0; k < tx.inputs.size(); k++) {
            ChainDB.UtxoEntry c = coins.get(k);
            st.sigops += HsScript.getSigops(c.addrVersion(), c.addrHash(), tx.inputs.get(k).witness);
        }
        if (st.sigops > st.maxSigops) return failF("bad-blk-sigops", 100, i);

        // checkInputs
        long total = 0;
        for (ChainDB.UtxoEntry c : coins) {
            if (c.coinbase() && height - c.height() < p.coinbaseMaturity)
                return failF("bad-txns-premature-spend-of-coinbase", 0, i);
            if (c.value() < 0 || c.value() > ConsensusParams.MAX_MONEY) return failF("bad-txns-inputvalues-outofrange", 100, i);
            total += c.value();
            if (total < 0 || total > ConsensusParams.MAX_MONEY) return failF("bad-txns-inputvalues-outofrange", 100, i);
        }
        long outValue = 0;
        for (TxParser.Output o : tx.outputs) outValue += o.value;
        if (total < outValue) return failF("bad-txns-in-belowout", 100, i);
        long fee = total - outValue;
        if (fee > ConsensusParams.MAX_MONEY) return failF("bad-txns-fee-outofrange", 100, i);
        if (!ConsensusRules.verifyCovenantLinks(tx, coins)) return failF("bad-txns-covenants", 100, i);

        st.reward += fee; st.lastFee = fee;
        if (st.reward > ConsensusParams.MAX_MONEY) return failF("bad-cb-amount", 100, i);

        // name state (chain.verifyCovenants)
        ConsensusRules.Fail nf = NameRules.verify(tx, txid, st.names, height, nameFlags, p, chain, st.coinLookup);
        if (nf != null) return nf;

        for (int k = 0; k < tx.inputs.size(); k++) st.scriptJobs.add(new Spend(i, k, coins.get(k)));
        return null;
    }

    private static ConsensusRules.Fail failF(String reason, int score, int tx) {
        return new ConsensusRules.Fail(reason, score);
    }

    /**
     * Mempool-style validation of one loose transaction against {@code chain} (which may expose unconfirmed
     * parents): finality, input availability, sequence locks, maturity, values, covenant links, name rules and
     * script execution under {@code scriptFlags}. Returns null when valid. {@code feeOut[0]} receives the fee.
     */
    public static ConsensusRules.Fail validateTx(ChainCtx chain, ConsensusParams p, TxParser.ParsedTx tx, byte[] txid,
                                                 int height, long prevMtp, int scriptFlags, int nameFlags,
                                                 long[] feeOut) {
        St st = new St();
        st.created = new HashMap<>(); st.spent = new HashSet<>(); st.names = new NameRules.NameView(chain::name);
        st.scriptJobs = new ArrayList<>(); st.maxSigops = Long.MAX_VALUE;
        st.coinLookup = (t, ix) -> chain.utxo(t, ix);
        ConsensusRules.Fail f = txChecks(st, chain, p, tx, HexUtil.encode(txid), 0, height, prevMtp, nameFlags);
        if (f != null) return f;
        for (Spend sp : st.scriptJobs) {
            if (!HsScript.verifyInput(tx, sp.in, sp.coin.addrVersion(), sp.coin.addrHash(), sp.coin.value(), scriptFlags))
                return new ConsensusRules.Fail("mandatory-script-verify-flag-failed", 100);
        }
        if (feeOut != null && feeOut.length > 0) feeOut[0] = st.lastFee;
        return null;
    }

    private static Result fail(String reason, int score, int tx) {
        return new Result(new ConsensusRules.Fail(reason, score), 0, false, tx);
    }

    // ── ChainDB-backed context ───────────────────────────────────────────────

    public static ChainCtx dbContext(ChainDB db) {
        return new ChainCtx() {
            @Override public ChainDB.UtxoEntry utxo(String txid, int index) { return db.getUtxo(txid, index); }
            @Override public ChainDB.NameEntry name(byte[] nameHash) { return db.getNameByHash(nameHash); }
            @Override public long medianTimeAt(int height) { return BlockTemplates.medianTimePast(db, height); }
            @Override public int mainHeight(byte[] blockHash) {
                int h = db.getHeightByHash(blockHash);
                if (h < 0) return -1;
                byte[] hdr = db.getHeader(h);
                if (hdr == null || !Arrays.equals(HeaderUtil.hash(hdr), blockHash)) return -1;
                return h;
            }
        };
    }
}