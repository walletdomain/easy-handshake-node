package handshake.node.chain;

import handshake.node.storage.ChainDB;
import handshake.node.util.HexUtil;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Name-state consensus rules: a faithful port of hsd's chain.verifyCovenants()
 * (lib/blockchain/chain.js) together with the NameState helpers it relies on
 * (lib/covenants/namestate.js state/isExpired/maybeExpire/isClaimable and
 * rules.js isReserved/isLockedUp/hasRollout). It both CHECKS a transaction's
 * name covenants against the current name state and APPLIES the resulting
 * state change to a {@link NameView} overlay so later transactions in the same
 * block see it -- exactly what hsd does with its CoinView name cache.
 */
public final class NameRules {
    private NameRules() {}

    // hsd namestate.js states (note the numeric order: REDEEM checks state < CLOSED)
    public static final int OPENING = 0, LOCKED = 1, BIDDING = 2, REVEAL_S = 3, CLOSED = 4, REVOKED = 5;

    public static final int FLAG_HARDENED = 1;   // VERIFY_COVENANTS_HARDENED
    public static final int FLAG_LOCKUP = 2;     // VERIFY_COVENANTS_LOCKUP

    /** Read-through, copy-on-read overlay of name states for the block being validated. */
    public static final class NameView {
        public interface Source { ChainDB.NameEntry get(byte[] nameHash); }

        private final Source src;
        private final Map<String, ChainDB.NameEntry> overlay = new HashMap<>();

        public NameView(Source src) { this.src = src; }

        /** Mutable entry (changes persist in the overlay), or null if the name was never seen. */
        public ChainDB.NameEntry get(byte[] hash) {
            String k = HexUtil.encode(hash);
            ChainDB.NameEntry e = overlay.get(k);
            if (e != null) return e;
            if (overlay.containsKey(k)) return null;
            ChainDB.NameEntry loaded = src.get(hash);
            overlay.put(k, loaded);
            return loaded;
        }

        public void put(byte[] hash, ChainDB.NameEntry e) { overlay.put(HexUtil.encode(hash), e); }

        public Map<String, ChainDB.NameEntry> changed() { return overlay; }
    }

    /** Header lookup needed for renewal/claim commitments. */
    public interface MainChain {
        /** Height of a block hash on the current best chain, or -1. */
        int mainHeight(byte[] blockHash);
    }

    // ── NameState helpers ────────────────────────────────────────────────────

    static boolean ownerNull(ChainDB.NameEntry ns) { return ns.ownerTxid == null || ns.ownerTxid.isEmpty(); }

    static boolean ownerIs(ChainDB.NameEntry ns, TxParser.Input in) {
        return !ownerNull(ns) && ns.ownerIndex == in.prevIndex && ns.ownerTxid.equals(HexUtil.encode(in.prevHash));
    }

    static void setOwner(ChainDB.NameEntry ns, String txid, int index) { ns.ownerTxid = txid; ns.ownerIndex = index; }

    public static int state(ChainDB.NameEntry ns, int height, ConsensusParams p) {
        int openPeriod = p.treeInterval + 1;
        if (ns.revoked != 0) return REVOKED;
        if (ns.claimed != 0) {
            if (height < ns.height + p.lockupPeriod) return LOCKED;
            return CLOSED;
        }
        if (height < ns.height + openPeriod) return OPENING;
        if (height < ns.height + openPeriod + p.biddingPeriod) return BIDDING;
        if (height < ns.height + openPeriod + p.biddingPeriod + p.revealPeriod) return REVEAL_S;
        return CLOSED;
    }

    static boolean isClaimable(ChainDB.NameEntry ns, int height, ConsensusParams p) {
        return ns.claimed != 0 && !p.noReserved && height < p.claimPeriod;
    }

    static boolean isExpired(ChainDB.NameEntry ns, int height, ConsensusParams p) {
        if (ns.revoked != 0) return height >= ns.revoked + p.auctionMaturity;
        if (state(ns, height, p) != CLOSED) return false;
        if (isClaimable(ns, height, p)) return false;
        if (height >= ns.renewal + p.renewalWindow) return true;
        if (ownerNull(ns)) return true;
        return false;
    }

    static boolean maybeExpire(ChainDB.NameEntry ns, int height, ConsensusParams p) {
        if (!isExpired(ns, height, p)) return false;
        byte[] data = ns.resourceData;
        reset(ns, height);
        ns.expired = true;
        ns.resourceData = data == null ? new byte[0] : data;
        return true;
    }

    static void reset(ChainDB.NameEntry ns, int height) {
        ns.height = height;
        ns.renewal = height;
        ns.ownerTxid = null;
        ns.ownerIndex = 0;
        ns.value = 0;
        ns.highest = 0;
        ns.resourceData = new byte[0];
        ns.transfer = 0;
        ns.revoked = 0;
        ns.claimed = 0;
        ns.renewals = 0;
        ns.registered = false;
        ns.expired = false;
        ns.weak = false;
    }

    // ── rules.js name helpers ────────────────────────────────────────────────

    static boolean isReserved(byte[] nameHash, int height, ConsensusParams p) {
        if (p.noReserved) return false;
        if (height >= p.claimPeriod) return false;
        return ReservedNames.get(nameHash) != null;
    }

    static boolean isLockedUp(byte[] nameHash, int height, ConsensusParams p) {
        if (p.noReserved) return false;
        if (height < p.claimPeriod) return false;
        ReservedNames.Entry e = ReservedNames.get(nameHash);
        if (e == null || e.released) return false;
        if (e.root) return true;
        return height < p.alexaLockupPeriod;
    }

    static boolean hasRollout(byte[] nameHash, int height, ConsensusParams p) {
        if (p.noRollout) return true;
        int week = 0;
        int pm = 256 % 52, acc = 0;
        for (byte b : nameHash) acc = (pm * acc + (b & 0xff)) % 52;
        week = acc;
        int start = p.auctionStart + week * p.rolloutInterval;
        return height >= start;
    }

    /** chain.verifyRenewal */
    static boolean verifyRenewal(byte[] hash, int height, ConsensusParams p, MainChain chain) {
        if (height < p.renewalMaturity) return true;
        int h = chain.mainHeight(hash);
        if (h < 0) return false;
        if (h > height - p.renewalMaturity) return false;
        if (h < height - p.renewalPeriod) return false;
        return true;
    }

    private static ConsensusRules.Fail f(String r) { return new ConsensusRules.Fail(r, 100); }

    // ── chain.verifyCovenants (non-coinbase transactions) ────────────────────

    /**
     * Checks every name covenant in {@code tx} against {@code view} and applies
     * the state transitions to it. Returns null when valid.
     */
    public static ConsensusRules.Fail verify(TxParser.ParsedTx tx, String txid, NameView view, int height,
                                             int nameFlags, ConsensusParams p, MainChain chain,
                                             java.util.function.BiFunction<String, Integer, ChainDB.UtxoEntry> coinLookup) {
        boolean coinbase = ConsensusRules.isCoinbase(tx);
        for (int i = 0; i < tx.outputs.size(); i++) {
            TxParser.Output output = tx.outputs.get(i);
            TxParser.Covenant cov = output.covenant;
            if (!ConsensusRules.isName(cov.type)) continue;
            if (coinbase && cov.type != ConsensusRules.CLAIM) continue;

            byte[] nameHash = ConsensusRules.getHash(cov, 0);
            long start = ConsensusRules.getU32(cov, 1);
            ChainDB.NameEntry ns = view.get(nameHash);

            if (ns == null) {
                if (cov.type != ConsensusRules.CLAIM && cov.type != ConsensusRules.OPEN)
                    return new ConsensusRules.Fail("bad-name-state-missing", 100);
                ns = new ChainDB.NameEntry();
                byte[] name = ConsensusRules.item(cov, 2);
                ns.name = new String(name, StandardCharsets.ISO_8859_1);
                ns.nameHash = HexUtil.encode(nameHash);
                reset(ns, height);
                ns.state = "";
                view.put(nameHash, ns);
            }

            maybeExpire(ns, height, p);
            int st = state(ns, height, p);

            if (cov.type == ConsensusRules.CLAIM) {
                if (!coinbase) return new ConsensusRules.Fail("bad-claim-in-tx", 100);
                ConsensusRules.Fail cf = applyClaim(tx, txid, i, ns, nameHash, st, height, nameFlags, p, chain, coinLookup);
                if (cf != null) return cf;
                continue;
            }

            switch (cov.type) {
                case ConsensusRules.OPEN: {
                    if (st != OPENING) return f("bad-open-state");
                    if (ns.height != height) return f("bad-open-multiple");
                    if (!ns.expired && isReserved(nameHash, height, p)) return f("bad-open-reserved");
                    if ((nameFlags & FLAG_LOCKUP) != 0 && isLockedUp(nameHash, height, p)) return f("bad-open-lockedup");
                    if (!hasRollout(nameHash, height, p)) return f("bad-open-rollout");
                    break;
                }
                case ConsensusRules.BID: {
                    if (st != BIDDING) return f("bad-bid-state");
                    if (start != ns.height) return f("bad-bid-height");
                    break;
                }
                case ConsensusRules.REVEAL: {
                    TxParser.Input prevout = tx.inputs.get(i);
                    if (start != ns.height) return f("bad-reveal-nonlocal");
                    if (st != REVEAL_S) return f("bad-reveal-state");
                    if (ownerNull(ns) || output.value > ns.highest) {
                        ns.value = ns.highest;
                        setOwner(ns, txid, i);
                        ns.highest = output.value;
                    } else if (output.value > ns.value) {
                        ns.value = output.value;
                    }
                    break;
                }
                case ConsensusRules.REDEEM: {
                    TxParser.Input prevout = tx.inputs.get(i);
                    if (start != ns.height) return f("bad-redeem-nonlocal");
                    if (st < CLOSED) return f("bad-redeem-state");
                    if (ownerIs(ns, prevout)) return f("bad-redeem-owner");
                    break;
                }
                case ConsensusRules.REGISTER: {
                    TxParser.Input prevout = tx.inputs.get(i);
                    if (start != ns.height) return f("bad-register-nonlocal");
                    if (st != CLOSED) return f("bad-register-state");
                    byte[] data = ConsensusRules.item(cov, 2);
                    byte[] hash = ConsensusRules.getHash(cov, 3);
                    if (!verifyRenewal(hash, height, p, chain)) return f("bad-register-renewal");
                    if (!ownerIs(ns, prevout)) return f("bad-register-owner");
                    if (output.value != ns.value) return f("bad-register-value");
                    if (isClaimable(ns, height, p)) {
                        if ((nameFlags & FLAG_HARDENED) != 0 && ns.weak) return f("bad-register-state");
                    }
                    ns.registered = true;
                    setOwner(ns, txid, i);
                    if (data.length > 0) ns.resourceData = data;
                    ns.renewal = height;
                    break;
                }
                case ConsensusRules.UPDATE: {
                    if (start != ns.height) return f("bad-update-nonlocal");
                    if (st != CLOSED) return f("bad-update-state");
                    byte[] data = ConsensusRules.item(cov, 2);
                    setOwner(ns, txid, i);
                    if (data.length > 0) ns.resourceData = data;
                    ns.transfer = 0;
                    break;
                }
                case ConsensusRules.RENEW: {
                    if (start != ns.height) return f("bad-renewal-nonlocal");
                    if (st != CLOSED) return f("bad-renewal-state");
                    byte[] hash = ConsensusRules.getHash(cov, 2);
                    if (height < ns.renewal + p.treeInterval) return f("bad-renewal-premature");
                    if (!verifyRenewal(hash, height, p, chain)) return f("bad-renewal");
                    setOwner(ns, txid, i);
                    ns.transfer = 0;
                    ns.renewal = height;
                    ns.renewals = ns.renewals + 1;
                    break;
                }
                case ConsensusRules.TRANSFER: {
                    if (start != ns.height) return f("bad-transfer-nonlocal");
                    if (st != CLOSED) return f("bad-transfer-state");
                    if (ns.transfer != 0) return f("bad-transfer-state");
                    setOwner(ns, txid, i);
                    ns.transfer = height;
                    break;
                }
                case ConsensusRules.FINALIZE: {
                    if (start != ns.height) return f("bad-finalize-nonlocal");
                    if (st != CLOSED) return f("bad-finalize-state");
                    if (ns.transfer == 0) return f("bad-finalize-state");
                    if (height < ns.transfer + p.transferLockup) return f("bad-finalize-maturity");
                    int flags = ConsensusRules.getU8(cov, 3);
                    boolean weak = (flags & 1) != 0;
                    long claimed = ConsensusRules.getU32(cov, 4);
                    long renewals = ConsensusRules.getU32(cov, 5);
                    byte[] hash = ConsensusRules.getHash(cov, 6);
                    if (weak != ns.weak || claimed != (ns.claimed & 0xffffffffL) || renewals != (ns.renewals & 0xffffffffL))
                        return f("bad-finalize-statetransfer");
                    if (!verifyRenewal(hash, height, p, chain)) return f("bad-finalize-renewal");
                    setOwner(ns, txid, i);
                    ns.transfer = 0;
                    ns.renewal = height;
                    ns.renewals = ns.renewals + 1;
                    break;
                }
                case ConsensusRules.REVOKE: {
                    if (start != ns.height) return f("bad-revoke-nonlocal");
                    if (st != CLOSED) return f("bad-revoke-state");
                    if (ns.revoked != 0) return f("bad-revoke-state");
                    ns.revoked = height;
                    ns.transfer = 0;
                    ns.resourceData = new byte[0];
                    break;
                }
                default:
                    return f("bad-covenant-type");
            }
        }
        return null;
    }

    /** The CLAIM branch of chain.verifyCovenants (ownership PROOFS are not verified; see BlockValidator). */
    private static ConsensusRules.Fail applyClaim(TxParser.ParsedTx tx, String txid, int i, ChainDB.NameEntry ns,
                                                  byte[] nameHash, int st, int height, int nameFlags,
                                                  ConsensusParams p, MainChain chain,
                                                  java.util.function.BiFunction<String, Integer, ChainDB.UtxoEntry> coinLookup) {
        TxParser.Output output = tx.outputs.get(i);
        TxParser.Covenant cov = output.covenant;
        if (ConsensusRules.getU32(cov, 1) != (height & 0xffffffffL)) return new ConsensusRules.Fail("bad-txns-claims", 100);
        int flags = ConsensusRules.getU8(cov, 3);
        boolean weak = (flags & 1) != 0;
        boolean valid = st == OPENING || st == LOCKED || (st == CLOSED && !ns.registered);
        if (!valid) return f("bad-claim-state");
        if (ns.expired || !isReserved(nameHash, height, p)) return f("bad-claim-notreserved");
        if ((nameFlags & FLAG_HARDENED) != 0 && weak) return f("bad-claim-algorithm");
        byte[] block = ConsensusRules.getHash(cov, 4);
        int claimed = chain.mainHeight(block);
        if (claimed != (int) ConsensusRules.getU32(cov, 5)) return f("bad-claim-commit-height");
        if (claimed <= ns.claimed) return f("bad-claim-commit-hash");
        if (height >= p.deflationHeight) {
            if (ownerNull(ns)) {
                if (claimed != 1) return new ConsensusRules.Fail("bad-claim-height", 0);
            }
            if (!ownerNull(ns) && height < ns.height + p.claimFrequency) return new ConsensusRules.Fail("bad-claim-frequency", 0);
            if (!ownerNull(ns)) {
                ChainDB.UtxoEntry coin = coinLookup.apply(ns.ownerTxid, ns.ownerIndex);
                if (coin == null || output.value != coin.value()) return new ConsensusRules.Fail("bad-claim-value", 0);
            }
        }
        ns.height = height;
        ns.renewal = height;
        ns.claimed = claimed;
        ns.value = 0;
        setOwner(ns, txid, i);
        ns.highest = 0;
        ns.weak = weak;
        return null;
    }

    static byte[] ascii(String s) { return s.getBytes(StandardCharsets.ISO_8859_1); }
    static boolean eq(byte[] a, byte[] b) { return Arrays.equals(a, b); }
}