package handshake.node.chain;

import handshake.node.util.HexUtil;

import handshake.node.crypto.Blake2b;

import handshake.node.storage.ChainDB;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Mempool — in-memory pool of unconfirmed transactions.
 * <p>
 * Responsibilities:
 *   - Accept and validate incoming transactions
 *   - Relay valid transactions to peers
 *   - Provide transaction data for RPC queries
 *   - Evict transactions when a block confirms them
 *   - Track fee rates for mining prioritization
 * <p>
 * Validation checks performed:
 *   - Basic structure (inputs, outputs, version)
 *   - No double-spends against UTXO set
 *   - No double-spends within mempool
 *   - Covenant type rules (basic sanity)
 *   - Full, name-state-aware covenant validation (see CovenantValidator)
 *   - Minimum relay fee
 * <p>
 */
public class Mempool {

    // ── Constants (hsd lib/protocol/policy.js, consensus.js, networks.js main) ──

    private static final long   COIN                 = 1_000_000L;
    private static final long   MAX_MONEY            = 2_040_000_000L * COIN;
    private static final int    CONSENSUS_MAX_TX_SIZE   = 1_000_000;   // base size
    private static final int    CONSENSUS_MAX_TX_WEIGHT = 4_000_000;
    private static final int    POLICY_MAX_TX_WEIGHT    = 400_000;     // MAX_BLOCK_WEIGHT / 10
    private static final int    MAX_TX_SIGOPS           = 16_000;      // MAX_BLOCK_SIGOPS / 5
    private static final int    BYTES_PER_SIGOP         = 20;
    private static final int    MAX_BLOCK_OPENS         = 300;
    private static final int    MAX_BLOCK_UPDATES       = 600;
    private static final int    MAX_BLOCK_RENEWALS      = 600;
    private static final long   MIN_RELAY_FEE_KB = 1_000;     // doos per kvB (policy.MIN_RELAY)
    private static final long   ABSURD_FEE_FACTOR       = 10_000;
    private static final long   FREE_THRESHOLD          = COIN * 144 / 250;
    private static final long   LIMIT_FREE_RELAY        = 15;          // thousand bytes per minute
    private static final int    MAX_ANCESTORS           = 50;
    private static final long   MAX_MEMPOOL_BYTES       = 100L * 1_000_000;
    private static final long   EXPIRY_SECONDS          = 72L * 60 * 60;
    private static final int    MAX_ORPHANS             = 100;
    private static final int    MAX_P2WSH_STACK         = 100;
    private static final int    MAX_P2WSH_PUSH          = 80;
    private static final int    MAX_P2WSH_SIZE          = 3600;
    private static final int    MAX_REJECTS             = 120_000;

    /** Mirrors hsd's VerifyError: a short code (invalid, nonstandard, dust,
     *  insufficientfee, duplicate, alreadyknown, highfee), a reason string and a ban score. */
    public static final class VerifyException extends Exception {
        public final String code;
        public final String reason;
        public final int score;
        VerifyException(String code, String reason, int score) {
            super(reason);
            this.code = code; this.reason = reason; this.score = score;
        }
        /** hsd RejectPacket.codes; internal codes (alreadyknown, highfee...) go out as INVALID. */
        public int rejectCode() {
            return switch (code) {
                case "nonstandard" -> 0x40;
                case "dust" -> 0x41;
                case "insufficientfee" -> 0x42;
                case "duplicate" -> 0x12;
                case "malformed" -> 0x01;
                default -> 0x10;
            };
        }
    }

    // ── Entry ─────────────────────────────────────────────────────────────────

    public static class MempoolEntry {
        public final String txid;
        public final byte[] raw;
        public final long   fee;
        /** Virtual size as hsd counts it for fees and limits: (weight + 3) / 4,
         *  weight = base * 3 + total (witness data counts a quarter). */
        public final int    size;
        public final long   addedAt;
        public final int    height;   // block height when added

        public MempoolEntry(String txid, byte[] raw, long fee, int height) {
            this.txid    = txid;
            this.raw     = raw;
            this.fee     = fee;
            TxParser.ParsedTx p = TxParser.parse(raw);
            this.size    = p != null ? virtualSize(p) : raw.length;
            this.addedAt = System.currentTimeMillis();
            this.height  = height;
        }

        public String toJson(boolean verbose) {
            if (!verbose) return "\"" + txid + "\"";
            return "{"
                    + "\"size\":" + size + ","
                    + "\"fee\":" + (fee / 1_000_000.0) + ","
                    + "\"modifiedfee\":0,"
                    + "\"time\":" + (addedAt / 1000) + ","
                    + "\"height\":" + height + ","
                    + "\"descendantcount\":0,"
                    + "\"descendantsize\":" + size + ","
                    + "\"descendantfees\":" + fee + ","
                    + "\"ancestorcount\":0,"
                    + "\"ancestorsize\":0,"
                    + "\"ancestorfees\":0,"
                    + "\"depends\":[]"
                    + "}";
        }
    }

    static long weight(TxParser.ParsedTx t) {
        return (long) t.baseSize * 3 + t.totalSize;
    }

    public static int virtualSizeOf(TxParser.ParsedTx t) { return virtualSize(t); }

    static int virtualSize(TxParser.ParsedTx t) {
        return (int) ((weight(t) + 3) / 4);
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final ChainDB db;
    private final ConcurrentHashMap<String, MempoolEntry> entries = new ConcurrentHashMap<>();
    // Track spent outpoints to detect double-spends within mempool
    private final ConcurrentHashMap<String, String> spentOutpoints = new ConcurrentHashMap<>();

    // Relay callback — called when a valid tx should be relayed to peers
    private RelayCallback relayCallback;

    /** Separate from relayCallback (which is specifically for P2P
     *  relay, excluding the sender): a plain "a transaction was just
     *  accepted" notification, for the socket layer's mempool "tx"
     *  event -- doesn't need an excludeIp concept at all, since every
     *  connected socket client should hear about every accepted tx. */
    private final List<java.util.function.Consumer<MempoolEntry>> txListeners = new java.util.concurrent.CopyOnWriteArrayList<>();
    public void addTxListener(java.util.function.Consumer<MempoolEntry> listener) {
        txListeners.add(listener);
    }

    /**
     * excludeIp is the peer that sent us this transaction (so we don't
     * immediately bounce it right back to them), or null when the
     * transaction originated from our own RPC (sendrawtransaction), in
     * which case there's no sender to exclude.
     */
    public interface RelayCallback {
        void relay(String txid, byte[] raw, String excludeIp);
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    public Mempool(ChainDB db) {
        this.db = db;
        java.util.concurrent.ScheduledExecutorService flusher = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "mempool-log");
            t.setDaemon(true);
            return t;
        });
        flusher.scheduleWithFixedDelay(this::flushAcceptedLog, ACCEPT_LOG_FLUSH_MS, ACCEPT_LOG_FLUSH_MS,
                java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    // ── Compact "accepted" log ──
    // Accepted transactions arrive in bursts (a peer announces dozens at once). Instead of one line each, they are
    // counted per source and reported as one line per source every couple of seconds.
    private static final long ACCEPT_LOG_FLUSH_MS = 2_000;
    private final Map<String, Integer> acceptedPending = new LinkedHashMap<>();

    private void noteAccepted(String fromIp) {
        synchronized (acceptedPending) {
            acceptedPending.merge(fromIp == null || fromIp.isBlank() ? "local" : fromIp, 1, Integer::sum);
        }
    }

    private void flushAcceptedLog() {
        Map<String, Integer> batch;
        synchronized (acceptedPending) {
            if (acceptedPending.isEmpty()) return;
            batch = new LinkedHashMap<>(acceptedPending);
            acceptedPending.clear();
        }
        for (Map.Entry<String, Integer> e : batch.entrySet()) {
            System.out.printf("[Mempool] Accepted %d new transaction%s from %s%n",
                    e.getValue(), e.getValue() == 1 ? "" : "s", e.getKey());
        }
    }

    public void setRelayCallback(RelayCallback cb) {
        this.relayCallback = cb;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    // Name claims in the mempool (hsd ContractState.unique): one transaction at a time
    // may OPEN/REGISTER/UPDATE/RENEW/TRANSFER/FINALIZE/REVOKE a given name.
    private final Map<String, String> nameClaims = new HashMap<>();
    private final Map<String, TxParser.ParsedTx> parsedCache = new ConcurrentHashMap<>();
    private final Map<String, Orphan> orphans = new LinkedHashMap<>();
    private final Map<String, Set<String>> waiting = new HashMap<>();
    private final LinkedHashSet<String> rejects = new LinkedHashSet<>();
    private double freeCount = 0;
    private long lastFreeTime = System.currentTimeMillis() / 1000;
    private long totalRawBytes = 0;

    private static final class Orphan {
        final String txid; final byte[] raw; final String fromIp; final Set<String> missing;
        Orphan(String txid, byte[] raw, String fromIp, Set<String> missing) {
            this.txid = txid; this.raw = raw; this.fromIp = fromIp; this.missing = missing;
        }
    }

    /** A spendable output as the mempool sees it (chain UTXO or an output of another mempool tx). */
    private static final class Coin {
        long value; int addrVersion; byte[] addrHash; boolean coinbase; int height; boolean inMempool;
    }

    /** Result of trying to add a transaction. */
    private static final class Outcome {
        final String txid;            // set when accepted
        final List<String> missing;   // set when kept as an orphan (parents to request)
        Outcome(String txid, List<String> missing) { this.txid = txid; this.missing = missing; }
    }

    /**
     * Submits a raw transaction to the mempool (our own RPC / socket path).
     * Returns the txid if accepted, null if rejected.
     */
    public synchronized String submit(byte[] raw) {
        try {
            Outcome o = insert(raw, null);
            if (o.txid == null) {
                System.out.println("[Mempool] Rejected: missing inputs (kept as orphan)");
                return null;
            }
            return o.txid;
        } catch (VerifyException e) {
            System.out.printf("[Mempool] Rejected: %s%n", e.reason);
            return null;
        } catch (RuntimeException e) {
            System.out.printf("[Mempool] Rejected: %s%n", e);
            return null;
        }
    }

    /** Like {@link #submit} but says why: returns the txid, or throws the reason the transaction was refused
     *  (an orphan -- parents unknown -- is reported as missing inputs). */
    public synchronized String submitOrThrow(byte[] raw) throws VerifyException {
        Outcome o = insert(raw, null);
        if (o.txid == null) throw new VerifyException("invalid", "bad-txns-inputs-missingorspent", 0);
        return o.txid;
    }

    /** Peer-sourced transaction counters, shown in the periodic stats line. */
    private final java.util.concurrent.atomic.AtomicInteger peerTxReceived = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger peerTxAccepted = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger peerTxRejected = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicInteger peerTxDuplicate = new java.util.concurrent.atomic.AtomicInteger();
    private volatile long rejectLogWindowStart = 0;
    private int rejectLogsInWindow = 0;

    public String peerTxStats() {
        return peerTxReceived.get() + " received from peers, " + peerTxAccepted.get()
                + " accepted, " + peerTxDuplicate.get() + " duplicate, " + peerTxRejected.get() + " rejected";
    }

    /** What happened to a transaction a peer sent us (mirrors hsd Pool._handleTX). */
    public static final class PeerTxResult {
        /** txid (hex) if accepted, else null. */
        public final String txid;
        /** Non-null when the tx should be answered with a REJECT packet (every hsd VerifyError is). */
        public final String rejectReason;
        /** hsd reject code (RejectPacket.codes): 0x01 malformed, 0x10 invalid, 0x12 duplicate, 0x40 nonstandard, 0x41 dust, 0x42 insufficient fee. */
        public final int rejectCode;
        /** Ban score hsd adds for this error (a peer reaching 100 is banned). */
        public final int score;
        /** The 32-byte txid to put in the REJECT packet (all zero if it could not be computed). */
        public final byte[] txidBytes;
        /** Parent txids to request (hex) when the tx was kept as an orphan; empty otherwise. */
        public final List<String> missing;
        PeerTxResult(String txid, String rejectReason, int rejectCode, int score, byte[] txidBytes, List<String> missing) {
            this.txid = txid; this.rejectReason = rejectReason; this.rejectCode = rejectCode;
            this.score = score; this.txidBytes = txidBytes; this.missing = missing;
        }
    }

    public String submitFromPeer(byte[] raw, String fromIp) {
        return submitFromPeerChecked(raw, fromIp).txid;
    }

    /** Same as submitFromPeer(), but also says whether (and how) to REJECT, as hsd does. */
    public synchronized PeerTxResult submitFromPeerChecked(byte[] raw, String fromIp) {
        peerTxReceived.incrementAndGet();
        byte[] idBytes = new byte[32];
        try { idBytes = HexUtil.decode(computeTxid(raw)); } catch (Exception ignored) { }
        try {
            Outcome o = insert(raw, fromIp);
            if (o.txid != null) {
                peerTxAccepted.incrementAndGet();
                return new PeerTxResult(o.txid, null, 0, 0, idBytes, List.of());
            }
            return new PeerTxResult(null, null, 0, 0, idBytes, o.missing);
        } catch (VerifyException e) {
            String why = e.reason;
            // A copy of a transaction we already hold (or that is already confirmed) is not a rejection: it is
            // counted on its own and the sender gets no REJECT for it (several peers often send the same one).
            if (why.equals("txn-already-in-mempool") || why.equals("txn-already-known")) {
                peerTxDuplicate.incrementAndGet();
                return new PeerTxResult(null, null, 0, 0, idBytes, List.of());
            }
            // hsd: every other VerifyError is answered with a REJECT and adds the error's ban score.
            peerTxRejected.incrementAndGet();
            long now = System.currentTimeMillis();
            if (now - rejectLogWindowStart > 60_000) { rejectLogWindowStart = now; rejectLogsInWindow = 0; }
            if (rejectLogsInWindow++ < 10 && !why.equals("txn-already-in-mempool")) {
                System.out.printf("[Mempool] Rejected tx from %s: %s (code=%s score=%d)%n", fromIp, why, e.code, e.score);
            }
            String reason = why.length() > 100 ? why.substring(0, 100) : why;
            reason = reason.replaceAll("[^\\x20-\\x7E]", "?");
            return new PeerTxResult(null, reason, e.rejectCode(), e.score, idBytes, List.of());
        } catch (RuntimeException e) {
            peerTxRejected.incrementAndGet();
            System.out.printf("[Mempool] Error handling tx from %s: %s%n", fromIp, e);
            return new PeerTxResult(null, "malformed", 0x01, 10, idBytes, List.of());
        }
    }

    /** True if we recently refused this transaction (hsd's recent-rejects filter), so a
     *  peer's announcement of it need not be fetched again. */
    public synchronized boolean hasReject(String txid) {
        return rejects.contains(txid);
    }

    public synchronized int rejectCount() { return rejects.size(); }
    public static int rejectLimit() { return MAX_REJECTS; }

    private void addReject(String txid) {
        rejects.add(txid);
        if (rejects.size() > MAX_REJECTS) {
            Iterator<String> it = rejects.iterator();
            it.next(); it.remove();
        }
    }

    // ── Insertion (hsd Mempool.insertTX / verify) ────────────────────────────

    private Outcome insert(byte[] raw, String fromIp) throws VerifyException {
        TxParser.ParsedTx tx;
        try {
            tx = TxParser.parse(raw);
        } catch (RuntimeException e) {
            tx = null;
        }
        if (tx == null) throw new VerifyException("malformed", "Failed to parse transaction", 10);
        String txid = computeTxid(raw);
        try {
            Outcome o = insertParsed(tx, raw, txid, fromIp);
            if (o.txid != null) resolveOrphans(txid);
            return o;
        } catch (VerifyException e) {
            if (!e.code.equals("alreadyknown") && !e.code.equals("duplicate")) addReject(txid);
            throw e;
        }
    }

    private Outcome insertParsed(TxParser.ParsedTx tx, byte[] raw, String txid, String fromIp) throws VerifyException {
        int tip = db.getBlockTip();
        int height = tip + 1;

        // Basic sanity (tx.checkSanity) -- important: later arithmetic cannot overflow.
        checkSanity(tx);

        // Coinbases are an insta-ban.
        if (tx.inputs.get(0).isCoinbase()) throw new VerifyException("invalid", "coinbase", 100);

        // Non-contextual standardness (network.requireStandard is true on mainnet).
        checkStandard(tx);

        // Finality (locktime), judged at the next block with median-time-past.
        long mtp;
        try { mtp = BlockTemplates.medianTimePast(db, tip); } catch (RuntimeException e) { mtp = 0; }
        if (!BlockTemplates.isFinal(tx, height, mtp)) throw new VerifyException("nonstandard", "non-final", 0);

        if (entries.containsKey(txid)) throw new VerifyException("alreadyknown", "txn-already-in-mempool", 0);

        // Enforce unique names.
        for (String nh : uniqueNameHashes(tx)) {
            if (nameClaims.containsKey(nh)) throw new VerifyException("alreadyknown", "name-already-in-mempool", 0);
        }

        // Non-fully-spent transaction already on chain.
        for (int i = 0; i < tx.outputs.size(); i++) {
            if (db.getUtxo(txid, i) != null) throw new VerifyException("alreadyknown", "txn-already-known", 0);
        }

        // Double-spend of an output already spent in the mempool.
        for (TxParser.Input in : tx.inputs) {
            if (spentOutpoints.containsKey(in.prevTxid + ":" + in.prevIndex)) {
                throw new VerifyException("duplicate", "bad-txns-inputs-spent", 0);
            }
        }

        // Coin view as the mempool sees it.
        Coin[] coins = new Coin[tx.inputs.size()];
        Set<String> missing = new LinkedHashSet<>();
        for (int i = 0; i < coins.length; i++) {
            coins[i] = findCoin(tx.inputs.get(i));
            if (coins[i] == null) missing.add(tx.inputs.get(i).prevTxid);
        }
        if (!missing.isEmpty()) {
            return maybeOrphan(tx, raw, txid, fromIp, missing);
        }

        // ── Contextual verification (hsd Mempool.verify) ──
        // Standard inputs.
        if (!hasStandardInputs(tx, coins)) throw new VerifyException("nonstandard", "bad-txns-nonstandard-inputs", 0);

        int sigops = 0;
        for (int i = 0; i < coins.length; i++) if (coins[i].addrVersion == 0 && coins[i].addrHash.length == 20) sigops++;
        if (sigops > MAX_TX_SIGOPS) throw new VerifyException("nonstandard", "bad-txns-too-many-sigops", 0);

        long weight = weight(tx);
        int size = (int) ((Math.max(weight, (long) sigops * BYTES_PER_SIGOP) + 3) / 4);

        // Input values and fee (tx.checkInputs).
        long inputValue = 0;
        for (Coin c : coins) {
            if (c.coinbase && !c.inMempool && height - c.height < BlockProcessor.params.coinbaseMaturity) {
                throw new VerifyException("invalid", "bad-txns-premature-spend-of-coinbase", 0);
            }
            if (c.value < 0 || c.value > MAX_MONEY) throw new VerifyException("invalid", "bad-txns-inputvalues-outofrange", 100);
            inputValue += c.value;
            if (inputValue < 0 || inputValue > MAX_MONEY) throw new VerifyException("invalid", "bad-txns-inputvalues-outofrange", 100);
        }
        long outputValue = 0;
        for (TxParser.Output o : tx.outputs) outputValue += o.value;
        if (inputValue < outputValue) throw new VerifyException("invalid", "bad-txns-in-belowout", 100);
        long fee = inputValue - outputValue;
        if (fee > MAX_MONEY) throw new VerifyException("invalid", "bad-txns-fee-outofrange", 100);

        // Fee policy.
        long minFee = Math.floorDiv(MIN_RELAY_FEE_KB * size, 1000L);
        if (minFee == 0 && MIN_RELAY_FEE_KB > 0) minFee = MIN_RELAY_FEE_KB;
        long absurdFee = minFee * ABSURD_FEE_FACTOR;
        if (fee < minFee) {
            // relayPriority: a very-low-fee transaction must be "free" by coin age priority.
            long chainValue = 0, sum = 0;
            for (int i = 0; i < coins.length; i++) {
                if (coins[i].inMempool) continue;
                chainValue += coins[i].value;
                if (coins[i].height <= tip) sum += coins[i].value * (long) (tip - coins[i].height);
            }
            long priority = Math.floorDiv(sum, size) + Math.floorDiv(chainValue, size); // age grows by one block at insertion
            if (priority <= FREE_THRESHOLD) throw new VerifyException("insufficientfee", "insufficient priority", 0);
            // limitFree: exponentially decaying rate limit on free transactions.
            long now = System.currentTimeMillis() / 1000;
            freeCount *= Math.pow(1 - 1.0 / 600, now - lastFreeTime);
            lastFreeTime = now;
            if (freeCount > LIMIT_FREE_RELAY * 10 * 1000) {
                throw new VerifyException("insufficientfee", "rate limited free transaction", 0);
            }
            freeCount += size;
        }
        if (fee > absurdFee) throw new VerifyException("highfee", "absurdly-high-fee", 0);

        // Ancestors.
        if (countAncestors(tx) + 1 > MAX_ANCESTORS) {
            throw new VerifyException("nonstandard", "too-long-mempool-chain", 0);
        }

        // Full consensus + standardness verification: scripts under the STANDARD flags, covenant links and
        // name-state rules (the same code that validates blocks). Unconfirmed parents are visible as coins.
        verifyWithValidator(tx, txid, height, mtp);

        // ── Add and index the entry ──
        MempoolEntry entry = new MempoolEntry(txid, raw, fee, tip);
        // entry.size above is the plain virtual size; keep sigops-adjusted size in the map for limits.
        entries.put(txid, entry);
        parsedCache.put(txid, tx);
        totalRawBytes += raw.length;
        for (TxParser.Input in : tx.inputs) spentOutpoints.put(in.prevTxid + ":" + in.prevIndex, txid);
        for (String nh : uniqueNameHashes(tx)) nameClaims.put(nh, txid);

        noteAccepted(fromIp);

        // Trim size / expire; the new tx itself may be what gets evicted.
        if (limitSize(txid)) {
            throw new VerifyException("insufficientfee", "mempool full", 0);
        }

        if (relayCallback != null) relayCallback.relay(txid, raw, fromIp);
        for (var listener : txListeners) {
            try { listener.accept(entry); }
            catch (Exception e) { System.err.println("[Mempool] tx listener error: " + e.getMessage()); }
        }
        return new Outcome(txid, List.of());
    }


    /** Coins as the mempool sees them: chain UTXOs plus outputs of unconfirmed parents. */
    private BlockValidator.ChainCtx mempoolCtx(int height) {
        BlockValidator.ChainCtx base = BlockValidator.dbContext(db);
        return new BlockValidator.ChainCtx() {
            @Override public ChainDB.UtxoEntry utxo(String t, int i) {
                MempoolEntry parent = entries.get(t);
                if (parent != null) {
                    TxParser.ParsedTx pt = parsedCache.get(t);
                    if (pt == null) { pt = TxParser.parse(parent.raw); if (pt != null) parsedCache.put(t, pt); }
                    if (pt == null || i < 0 || i >= pt.outputs.size()) return null;
                    TxParser.Output o = pt.outputs.get(i);
                    if (BlockValidator.unspendable(o.addrVersion, o.covenant.type)) return null;
                    return new ChainDB.UtxoEntry(o.value, o.addrVersion, o.addrHash, o.covenant.type,
                            ConsensusRules.encodeCovenantItems(o.covenant), false, height);
                }
                return base.utxo(t, i);
            }
            @Override public ChainDB.NameEntry name(byte[] h) { return base.name(h); }
            @Override public long medianTimeAt(int h) { return base.medianTimeAt(h); }
            @Override public int mainHeight(byte[] h) { return base.mainHeight(h); }
        };
    }

    private void verifyWithValidator(TxParser.ParsedTx tx, String txid, int height, long mtp) throws VerifyException {
        byte[] id = HexUtil.decode(txid);
        BlockValidator.ChainCtx ctx = mempoolCtx(height);
        int nf = BlockProcessor.nameFlagsAt(height);
        ConsensusRules.Fail f = BlockValidator.validateTx(ctx, BlockProcessor.params, tx, id, height, mtp,
                HsScript.STANDARD_VERIFY_FLAGS, nf, null);
        if (f == null) return;
        if (f.reason().equals("mandatory-script-verify-flag-failed")) {
            // Fails only the standardness flags -> merely non-standard (hsd: non-mandatory-script-verify-flag).
            ConsensusRules.Fail g = BlockValidator.validateTx(ctx, BlockProcessor.params, tx, id, height, mtp,
                    HsScript.MANDATORY_VERIFY_FLAGS, nf, null);
            if (g == null) throw new VerifyException("nonstandard", "non-mandatory-script-verify-flag", 0);
            throw new VerifyException("invalid", "mandatory-script-verify-flag-failed", 100);
        }
        throw new VerifyException("invalid", f.reason(), f.score());
    }

    // ── Pieces of hsd's checks ───────────────────────────────────────────────

    private static void checkSanity(TxParser.ParsedTx tx) throws VerifyException {
        if (tx.inputs.isEmpty()) throw new VerifyException("invalid", "bad-txns-vin-empty", 100);
        if (tx.outputs.isEmpty()) throw new VerifyException("invalid", "bad-txns-vout-empty", 100);
        if (tx.baseSize > CONSENSUS_MAX_TX_SIZE) throw new VerifyException("invalid", "bad-txns-oversize", 100);
        if (weight(tx) > CONSENSUS_MAX_TX_WEIGHT) throw new VerifyException("invalid", "bad-txns-overweight", 100);
        int opens = 0, updates = 0, renewals = 0;
        for (TxParser.Output o : tx.outputs) {
            if (o.covenant == null) continue;
            switch (o.covenant.type) {
                case TxParser.COV_CLAIM, TxParser.COV_OPEN -> { updates++; if (o.covenant.type == TxParser.COV_OPEN) opens++; }
                case TxParser.COV_UPDATE, TxParser.COV_TRANSFER, TxParser.COV_REVOKE -> updates++;
                default -> { }
            }
            switch (o.covenant.type) {
                case TxParser.COV_REGISTER, TxParser.COV_RENEW, TxParser.COV_FINALIZE -> renewals++;
                default -> { }
            }
        }
        if (opens > MAX_BLOCK_OPENS) throw new VerifyException("invalid", "bad-txns-opens", 100);
        if (updates > MAX_BLOCK_UPDATES) throw new VerifyException("invalid", "bad-txns-updates", 100);
        if (renewals > MAX_BLOCK_RENEWALS) throw new VerifyException("invalid", "bad-txns-renewals", 100);
        long total = 0;
        for (TxParser.Output o : tx.outputs) {
            if (o.value < 0) throw new VerifyException("invalid", "bad-txns-vout-negative", 100);
            if (o.value > MAX_MONEY) throw new VerifyException("invalid", "bad-txns-vout-toolarge", 100);
            total += o.value;
            if (total < 0 || total > MAX_MONEY) throw new VerifyException("invalid", "bad-txns-txouttotal-toolarge", 100);
            if (o.addrVersion > 31 || o.addrHash == null || o.addrHash.length < 2 || o.addrHash.length > 40) {
                throw new VerifyException("invalid", "bad-txns-address-size", 100);
            }
        }
        Set<String> seen = new HashSet<>();
        for (TxParser.Input in : tx.inputs) {
            if (!seen.add(in.prevTxid + ":" + in.prevIndex)) {
                throw new VerifyException("invalid", "bad-txns-inputs-duplicate", 100);
            }
        }
    }

    private static void checkStandard(TxParser.ParsedTx tx) throws VerifyException {
        if (tx.version > 0) throw new VerifyException("nonstandard", "version", 0);
        if (weight(tx) > POLICY_MAX_TX_WEIGHT) throw new VerifyException("nonstandard", "tx-size", 0);
        int nulldata = 0;
        for (TxParser.Output o : tx.outputs) {
            boolean unknownAddr = o.addrVersion == 0 ? (o.addrHash.length != 20 && o.addrHash.length != 32) : o.addrVersion != 31;
            if (unknownAddr) throw new VerifyException("nonstandard", "address", 0);
            if (o.addrVersion == 31) { nulldata++; continue; }
            int type = o.covenant != null ? o.covenant.type : TxParser.COV_NONE;
            if (type > TxParser.COV_REVOKE) throw new VerifyException("nonstandard", "covenant", 0);
            if (isDust(o)) throw new VerifyException("dust", "dust", 0);
        }
        if (nulldata > 1) throw new VerifyException("nonstandard", "multi-op-return", 0);
    }

    private static int varintSize(long n) { return n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffffL ? 5 : 9; }

    /** hsd Output.isDust(MIN_RELAY): only plain and BID outputs can be dust. */
    private static boolean isDust(TxParser.Output o) {
        int type = o.covenant != null ? o.covenant.type : TxParser.COV_NONE;
        if (!(type == TxParser.COV_NONE || type == TxParser.COV_BID || type > TxParser.COV_REVOKE)) return false;
        if (o.addrVersion == 31) return false;
        int covItems = o.covenant != null ? o.covenant.items.size() : 0;
        int covSize = 0;
        if (o.covenant != null) for (TxParser.CovenantItem it : o.covenant.items) covSize += varintSize(it.data.length) + it.data.length;
        int size = 8 + (2 + o.addrHash.length) + 1 + varintSize(covItems) + covSize;
        size += 32 + 4 + 1 + (107 / 4) + 4;
        long minFee = Math.floorDiv(MIN_RELAY_FEE_KB * size, 1000L);
        if (minFee == 0) minFee = MIN_RELAY_FEE_KB;
        return o.value < 3 * minFee;
    }

    private static boolean hasStandardInputs(TxParser.ParsedTx tx, Coin[] coins) {
        for (int i = 0; i < tx.inputs.size(); i++) {
            List<byte[]> w = tx.inputs.get(i).witness;
            if (w.isEmpty()) continue;
            Coin c = coins[i];
            if (c.addrVersion != 0) continue;
            if (c.addrHash.length == 20) {
                if (w.size() != 2 || w.get(0).length != 65 || w.get(1).length != 33) return false;
            } else if (c.addrHash.length == 32) {
                if (w.size() - 1 > MAX_P2WSH_STACK) return false;
                for (int k = 0; k < w.size() - 1; k++) if (w.get(k).length > MAX_P2WSH_PUSH) return false;
                if (w.get(w.size() - 1).length > MAX_P2WSH_SIZE) return false;
            }
        }
        return true;
    }

    /** Name hashes this transaction claims uniquely (hsd rules.hasNames). */
    private static List<String> uniqueNameHashes(TxParser.ParsedTx tx) {
        List<String> r = new ArrayList<>();
        for (TxParser.Output o : tx.outputs) {
            if (o.covenant == null || o.covenant.items.isEmpty()) continue;
            switch (o.covenant.type) {
                case TxParser.COV_CLAIM, TxParser.COV_OPEN, TxParser.COV_REGISTER, TxParser.COV_UPDATE,
                     TxParser.COV_RENEW, TxParser.COV_TRANSFER, TxParser.COV_FINALIZE, TxParser.COV_REVOKE ->
                        r.add(HexUtil.encode(o.covenant.items.get(0).data));
                default -> { }
            }
        }
        return r;
    }

    private Coin findCoin(TxParser.Input in) {
        MempoolEntry parent = entries.get(in.prevTxid);
        if (parent != null) {
            TxParser.ParsedTx pt = parsedCache.get(in.prevTxid);
            if (pt == null) { pt = TxParser.parse(parent.raw); parsedCache.put(in.prevTxid, pt); }
            if (in.prevIndex < 0 || in.prevIndex >= pt.outputs.size()) return null;
            TxParser.Output po = pt.outputs.get(in.prevIndex);
            Coin c = new Coin();
            c.value = po.value; c.addrVersion = po.addrVersion; c.addrHash = po.addrHash;
            c.coinbase = false; c.height = -1; c.inMempool = true;
            return c;
        }
        ChainDB.UtxoEntry u = db.getUtxo(in.prevTxid, in.prevIndex);
        if (u == null) return null;
        Coin c = new Coin();
        c.value = u.value(); c.addrVersion = u.addrVersion(); c.addrHash = u.addrHash();
        c.coinbase = u.coinbase(); c.height = u.height(); c.inMempool = false;
        return c;
    }

    private int countAncestors(TxParser.ParsedTx tx) {
        Set<String> seen = new HashSet<>();
        Deque<TxParser.ParsedTx> queue = new ArrayDeque<>();
        queue.add(tx);
        while (!queue.isEmpty() && seen.size() <= MAX_ANCESTORS + 1) {
            TxParser.ParsedTx t = queue.poll();
            for (TxParser.Input in : t.inputs) {
                if (!entries.containsKey(in.prevTxid) || !seen.add(in.prevTxid)) continue;
                TxParser.ParsedTx pt = parsedCache.get(in.prevTxid);
                if (pt != null) queue.add(pt);
            }
        }
        return seen.size();
    }

    // ── Orphans (hsd maybeOrphan / handleOrphans) ────────────────────────────

    private Outcome maybeOrphan(TxParser.ParsedTx tx, byte[] raw, String txid, String fromIp, Set<String> missing) {
        for (String parent : missing) {
            // A rejected parent, or a parent we hold that simply lacks the output: never store.
            if (rejects.contains(parent) || entries.containsKey(parent)) {
                addReject(txid);
                return new Outcome(null, List.of());
            }
        }
        if (weight(tx) > POLICY_MAX_TX_WEIGHT) return new Outcome(null, List.of());
        while (orphans.size() >= MAX_ORPHANS) {
            String victim = orphans.keySet().iterator().next();
            removeOrphan(victim);
        }
        orphans.put(txid, new Orphan(txid, raw, fromIp, new LinkedHashSet<>(missing)));
        for (String parent : missing) waiting.computeIfAbsent(parent, k -> new LinkedHashSet<>()).add(txid);
        return new Outcome(null, new ArrayList<>(missing));
    }

    private void removeOrphan(String txid) {
        Orphan o = orphans.remove(txid);
        if (o == null) return;
        for (String parent : o.missing) {
            Set<String> w = waiting.get(parent);
            if (w != null) { w.remove(txid); if (w.isEmpty()) waiting.remove(parent); }
        }
    }

    /** A transaction was accepted (or confirmed): orphans that were waiting on it may now go in. */
    private void resolveOrphans(String parentTxid) {
        Set<String> w = waiting.remove(parentTxid);
        if (w == null) return;
        for (String id : new ArrayList<>(w)) {
            Orphan o = orphans.get(id);
            if (o == null) continue;
            o.missing.remove(parentTxid);
            if (!o.missing.isEmpty()) continue;
            removeOrphan(id);
            try {
                insert(o.raw, o.fromIp);
            } catch (VerifyException e) {
                if (!e.code.equals("alreadyknown")) addReject(id);
            } catch (RuntimeException ignored) { }
        }
    }

    // ── Size limit and expiry (hsd limitSize) ────────────────────────────────

    private boolean hasDepends(String txid, TxParser.ParsedTx tx) {
        for (TxParser.Input in : tx.inputs) if (entries.containsKey(in.prevTxid)) return true;
        return false;
    }

    /** Removes expired and, if over the cap, the lowest fee-rate packages. True if the just-added tx was evicted. */
    private boolean limitSize(String added) {
        long now = System.currentTimeMillis();
        for (MempoolEntry e : new ArrayList<>(entries.values())) {
            TxParser.ParsedTx pt = parsedCache.get(e.txid);
            if (pt != null && hasDepends(e.txid, pt)) continue;
            if (now >= e.addedAt + EXPIRY_SECONDS * 1000) removeEntry(e.txid, true);
        }
        if (totalRawBytes <= MAX_MEMPOOL_BYTES) return !entries.containsKey(added);
        long threshold = MAX_MEMPOOL_BYTES - MAX_MEMPOOL_BYTES / 10;
        List<MempoolEntry> candidates = new ArrayList<>();
        for (MempoolEntry e : entries.values()) {
            TxParser.ParsedTx pt = parsedCache.get(e.txid);
            if (pt != null && hasDepends(e.txid, pt)) continue;
            candidates.add(e);
        }
        candidates.sort(Comparator.comparingDouble(e -> (double) e.fee / Math.max(1, e.size)));
        for (MempoolEntry e : candidates) {
            if (totalRawBytes <= threshold) break;
            removeEntry(e.txid, true);
        }
        return !entries.containsKey(added);
    }

    /** Removes an entry (and, if asked, every transaction spending its outputs). */
    private void removeEntry(String txid, boolean withDescendants) {
        MempoolEntry e = entries.remove(txid);
        if (e == null) return;
        TxParser.ParsedTx tx = parsedCache.remove(txid);
        if (tx == null) tx = TxParser.parse(e.raw);
        totalRawBytes -= e.raw.length;
        if (tx == null) return;
        for (TxParser.Input in : tx.inputs) spentOutpoints.remove(in.prevTxid + ":" + in.prevIndex);
        for (String nh : uniqueNameHashes(tx)) nameClaims.remove(nh, txid);
        if (withDescendants) {
            for (int i = 0; i < tx.outputs.size(); i++) {
                String child = spentOutpoints.get(txid + ":" + i);
                if (child != null) removeEntry(child, true);
            }
        }
    }

    // ── Block confirmation ────────────────────────────────────────────────────

    /**
     * Called when a block is connected: drops confirmed transactions, anything
     * that now conflicts with the chain, expired transactions, and releases
     * orphans whose parents just confirmed.
     */
    public synchronized void onBlockConnected(List<String> confirmedTxids) {
        for (String txid : confirmedTxids) {
            // Orphans waiting on a transaction that just confirmed can now be tried.
            removeEntry(txid, false);
        }
        // Anything left that spends an output which is neither on chain nor in the mempool is gone.
        for (MempoolEntry e : new ArrayList<>(entries.values())) {
            TxParser.ParsedTx pt = parsedCache.get(e.txid);
            if (pt == null) { pt = TxParser.parse(e.raw); if (pt != null) parsedCache.put(e.txid, pt); }
            if (pt == null) continue;
            for (TxParser.Input in : pt.inputs) {
                if (entries.containsKey(in.prevTxid)) continue;
                if (db.getUtxo(in.prevTxid, in.prevIndex) == null) { removeEntry(e.txid, true); break; }
            }
        }
        limitSize("");
        rejects.clear(); // hsd resets its reject filter on every new block
        for (String txid : confirmedTxids) resolveOrphans(txid);
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public byte[] getRaw(String txid) {
        MempoolEntry e = entries.get(txid);
        return e != null ? e.raw : null;
    }

    public MempoolEntry getEntry(String txid) {
        return entries.get(txid);
    }

    public String getEntryJson(String txid) {
        MempoolEntry e = entries.get(txid);
        return e != null ? e.toJson(true) : null;
    }

    public boolean contains(String txid) {
        return entries.containsKey(txid);
    }

    public int size() { return entries.size(); }

    /** Total serialized size (bytes) of everything currently in the
     *  mempool, for getmempoolinfo. */
    public int getTotalBytes() {
        return (int) Math.min(Integer.MAX_VALUE, totalRawBytes);
    }

    public long getMaxSize() { return MAX_MEMPOOL_BYTES; }
    public long getMinRelayFee() { return MIN_RELAY_FEE_KB; }

    public Collection<MempoolEntry> getAll() {
        return Collections.unmodifiableCollection(entries.values());
    }

    public String toJson(boolean verbose) {
        if (!verbose) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (String txid : entries.keySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(txid).append("\"");
                first = false;
            }
            return sb.append("]").toString();
        }
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (MempoolEntry e : entries.values()) {
            if (!first) sb.append(",");
            sb.append("\"").append(e.txid).append("\":");
            sb.append(e.toJson(true));
            first = false;
        }
        return sb.append("}").toString();
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static String computeTxid(byte[] raw) {
        // Parse base size from tx, hash base portion
        TxParser.ParsedTx tx = TxParser.parse(raw);
        if (tx == null) {
            return hex(Blake2b.hash256(raw));
        }
        byte[] base = Arrays.copyOf(raw, tx.baseSize);
        return hex(Blake2b.hash256(base));
    }

    private static String hex(byte[] b) {
        return HexUtil.encode(b);
    }
}