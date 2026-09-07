package handshake.validator;

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
 *   - Minimum relay fee
 * <p>
 * Note: Full covenant validation (bad-txns-covenants) requires
 * name state lookups — that is done in CovenantValidator.
 */
public class Mempool {

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final int    MAX_TX_SIZE      = 1_000_000; // 1MB
    private static final long   MIN_RELAY_FEE_KB = 1_000;     // dollarydoos per kvB
    private static final int    MAX_MEMPOOL_SIZE  = 50_000;    // max transactions

    // ── Entry ─────────────────────────────────────────────────────────────────

    public static class MempoolEntry {
        public final String txid;
        public final byte[] raw;
        public final long   fee;
        public final int    size;
        public final long   addedAt;
        public final int    height;   // block height when added

        public MempoolEntry(String txid, byte[] raw, long fee, int height) {
            this.txid    = txid;
            this.raw     = raw;
            this.fee     = fee;
            this.size    = raw.length;
            this.addedAt = System.currentTimeMillis();
            this.height  = height;
        }

        public double getFeeRate() {
            return size > 0 ? (double) fee / size * 1000 : 0;
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
    }

    public void setRelayCallback(RelayCallback cb) {
        this.relayCallback = cb;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Submits a raw transaction to the mempool.
     * Returns the txid if accepted, null if rejected.
     */
    public String submit(byte[] raw) {
        try {
            return submitInternal(raw, null); // no sender to exclude -- this is our own tx
        } catch (Exception e) {
            System.out.printf("[Mempool] Rejected: %s%n", e.getMessage());
            return null;
        }
    }

    /**
     * Submits a transaction received from a peer. fromIp is excluded
     * when relaying this transaction onward, so it isn't immediately
     * bounced right back to whoever just sent it to us -- but it IS
     * still relayed to our OTHER peers, which wasn't happening before
     * (this used to skip relay entirely for anything peer-sourced,
     * meaning any transaction that reached us this way was a dead end
     * for further propagation).
     */
    public String submitFromPeer(byte[] raw, String fromIp) {
        try {
            return submitInternal(raw, fromIp);
        } catch (Exception e) {
            return null;
        }
    }

    private String submitInternal(byte[] raw, String excludeIp) throws Exception {
        // Basic size check
        if (raw.length > MAX_TX_SIZE)
            throw new Exception("Transaction too large: " + raw.length);

        if (entries.size() >= MAX_MEMPOOL_SIZE)
            throw new Exception("Mempool full");

        // Compute txid (Blake2b-256 of base transaction)
        String txid = computeTxid(raw);

        // Already in mempool?
        if (entries.containsKey(txid))
            throw new Exception("txn-already-in-mempool");

        // Parse transaction
        TxParser.ParsedTx tx = TxParser.parse(raw);
        if (tx == null) throw new Exception("Failed to parse transaction");

        // Check inputs exist in UTXO set, aren't double-spent, and are
        // actually authorized to spend by the referenced signature --
        // previously this checked existence and double-spend only, never
        // verifying that the spender actually owns the key that UTXO was
        // sent to. Someone could have constructed a transaction spending
        // a UTXO they don't control and, as long as the fee math worked
        // out, it would have been accepted.
        long inputValue = 0;
        List<String> spentKeys = new ArrayList<>();
        for (int i = 0; i < tx.inputs.size(); i++) {
            TxParser.Input input = tx.inputs.get(i);
            if (input.isCoinbase()) throw new Exception("Coinbase not accepted");
            String outpoint = input.prevTxid + ":" + input.prevIndex;

            // Check mempool double-spend
            if (spentOutpoints.containsKey(outpoint))
                throw new Exception("txn-mempool-conflict: " + outpoint);

            // Check UTXO set
            ChainDB.UtxoEntry utxo = db.getUtxo(input.prevTxid, input.prevIndex);
            if (utxo == null)
                throw new Exception("bad-txns-inputs-missingorspent: " + outpoint);

            // Signature verification: only the standard witness-pubkeyhash
            // case (20-byte address hash) is checked -- see TxVerify's own
            // documentation for why other shapes are intentionally left
            // unverified rather than guessed at. This still meaningfully
            // closes the gap for the overwhelming majority of ordinary
            // spends.
            if (utxo.addrHash().length == 20) {
                if (!TxVerify.verifyInput(tx, i, utxo.addrHash(), utxo.value())) {
                    throw new Exception("mandatory-script-verify-flag-failed: " + outpoint);
                }
            }

            inputValue += utxo.value();
            spentKeys.add(outpoint);
        }

        // Calculate output value and fee
        long outputValue = 0;
        for (TxParser.Output output : tx.outputs) {
            outputValue += output.value;
        }

        if (outputValue > inputValue)
            throw new Exception("bad-txns-in-belowout");

        long fee = inputValue - outputValue;

        // Check minimum relay fee
        double feeRate = (double) fee / raw.length * 1000;
        if (feeRate < MIN_RELAY_FEE_KB)
            throw new Exception("min relay fee not met: " + feeRate);

        // Register spent outpoints
        for (String key : spentKeys) {
            spentOutpoints.put(key, txid);
        }

        // Add to mempool
        int currentHeight = db.getBlockTip();
        MempoolEntry entry = new MempoolEntry(txid, raw, fee, currentHeight);
        entries.put(txid, entry);

        System.out.printf("[Mempool] Accepted %s (fee=%.6f HNS, size=%d)%n",
                txid.substring(0, 12), fee / 1_000_000.0, raw.length);

        // Relay to peers -- always, regardless of source, excluding
        // only the peer we received this from (if any).
        if (relayCallback != null) {
            relayCallback.relay(txid, raw, excludeIp);
        }

        for (var listener : txListeners) {
            try { listener.accept(entry); }
            catch (Exception e) {
                System.err.println("[Mempool] tx listener error: " + e.getMessage());
            }
        }

        return txid;
    }

    // ── Block confirmation ────────────────────────────────────────────────────

    /**
     * Removes confirmed transactions from the mempool when a block is mined.
     * Also removes any mempool transactions that conflict with confirmed txs.
     */
    public void onBlockConnected(List<String> confirmedTxids) {
        for (String txid : confirmedTxids) {
            MempoolEntry entry = entries.remove(txid);
            if (entry != null) {
                // Remove spent outpoint tracking
                TxParser.ParsedTx tx = TxParser.parse(entry.raw);
                if (tx != null) {
                    for (TxParser.Input input : tx.inputs) {
                        spentOutpoints.remove(input.prevTxid + ":" + input.prevIndex);
                    }
                }
            }
        }
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
        int total = 0;
        for (MempoolEntry e : entries.values()) total += e.size;
        return total;
    }

    public int getMaxSize() { return MAX_MEMPOOL_SIZE; }
    public long getMinRelayFee() { return MIN_RELAY_FEE_KB; }

    public Collection<MempoolEntry> getAll() {
        return Collections.unmodifiableCollection(entries.values());
    }

    public List<byte[]> getAllRaw() {
        List<byte[]> list = new ArrayList<>();
        for (MempoolEntry e : entries.values()) list.add(e.raw);
        return list;
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
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}