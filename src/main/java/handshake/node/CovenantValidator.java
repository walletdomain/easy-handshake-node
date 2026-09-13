package handshake.node;

import java.util.List;

/**
 * Validates whether a name covenant is actually LEGAL to admit into the
 * mempool right now -- as opposed to Mempool's existing checks (structure,
 * double-spend, basic covenant type sanity, fee), and separately from
 * BlockProcessor.processNameCovenant(), which applies state transitions
 * unconditionally, trusting that anything reaching it already passed
 * consensus by virtue of being in a mined block.
 *
 * That trust is exactly right for block processing but was never
 * available at mempool-admission time -- Mempool's own class comment
 * already flagged this as a known gap ("Full covenant validation
 * (bad-txns-covenants) requires name state lookups"), referencing this
 * class by name before it existed. Without it, a wallet-broadcast
 * transaction with a genuinely invalid covenant (a BID submitted after
 * the bidding window closed, a REGISTER submitted mid-auction, and so
 * on) would sit in mempools across the network relaying harmlessly but
 * uselessly, since real nodes doing full block validation would reject
 * it at mining time regardless -- annoying for the wallet user, not a
 * funds-at-risk issue, but a real gap worth closing so the rejection
 * happens immediately and visibly instead.
 *
 * Deliberately built on top of BlockProcessor's own computeState()/
 * isExpired() rather than a second, parallel state machine -- those were
 * already ported from and verified against real hsd's namestate.js
 * (state()/isExpired()/maybeExpire()), including the exact mainnet
 * timing constants (confirmed directly from networks.js: biddingPeriod=
 * 5 days, revealPeriod=10 days, treeInterval=blocksPerDay/4=36, i.e.
 * this project's own existing TREE_INTERVAL -- an independent
 * cross-check that those constants were already right). Reusing them
 * here means this validator and actual block processing can never
 * silently drift apart on what "legal" means.
 *
 * Scope, stated plainly: this checks state-window timing (is this
 * covenant type legal for the name's CURRENT auction/registration state,
 * at the height this transaction would actually confirm) and basic
 * registration-status gating (e.g. RENEW/TRANSFER/UPDATE require an
 * already-registered name). It does NOT yet verify the REVEAL-matches-
 * BID blind commitment (the cryptographic auction-privacy check -- hash
 * of value+nonce against the BID's committed blind), nor does it verify
 * that a REGISTER/REDEEM is coming from the actual auction winner/loser
 * specifically, beyond Mempool's own existing signature check that
 * whoever is spending a UTXO genuinely controls it. Those are real,
 * separate pieces of real hsd's own verifyCovenants() this doesn't
 * attempt yet -- deliberately scoped out rather than guessed at, same
 * reasoning as MerkleBlock's auto-update flags being left for later.
 */
public class CovenantValidator {

    /** Returns null if this covenant is valid to admit right now, or a
     *  short, hsd-reject-code-style reason string if not.
     *
     *  mempoolHeight should be the height this transaction would
     *  actually confirm at if mined immediately -- current tip + 1, the
     *  same convention BlockProcessor uses when it processes an actual
     *  block at that height. Passing the current tip height itself
     *  (rather than +1) would reject transactions that are only one
     *  block away from a state-window boundary opening up, which is a
     *  real, if narrow, difference worth getting right. */
    public static String validate(TxParser.Output out, ChainDB db, int mempoolHeight) {
        int type = out.covenant.type;
        if (type != TxParser.COV_OPEN && type != TxParser.COV_BID && type != TxParser.COV_REVEAL
                && type != TxParser.COV_REDEEM && type != TxParser.COV_REGISTER
                && type != TxParser.COV_RENEW && type != TxParser.COV_TRANSFER
                && type != TxParser.COV_FINALIZE && type != TxParser.COV_REVOKE
                && type != TxParser.COV_UPDATE) {
            return null; // NONE/CLAIM: not this validator's concern
        }

        List<TxParser.CovenantItem> items = out.covenant.items;
        if (items.isEmpty()) return "bad-txns-covenant-malformed";
        byte[] nameHashBytes = items.get(0).data;
        if (nameHashBytes == null || nameHashBytes.length != 32) return "bad-txns-covenant-malformed";
        String nameHash = hex(nameHashBytes);

        ChainDB.NameEntry entry = db.getNameByHash(nameHash);
        boolean expired = entry != null && BlockProcessor.isExpired(entry, mempoolHeight);
        int state = entry != null ? BlockProcessor.computeState(entry, mempoolHeight) : -1;

        switch (type) {
            case TxParser.COV_OPEN -> {
                // Matches real hsd's own OPEN gate exactly: isNull() ||
                // isExpired() -- a name is only available to be opened
                // if it's never been touched, or its previous auction
                // fully expired (no reveals and the renewal window
                // lapsed, or a revocation aged past auctionMaturity).
                if (entry != null && !expired) {
                    return "bad-txns-open-not-available: name is currently "
                            + stateName(state) + ", not available to open";
                }
            }
            case TxParser.COV_BID -> {
                if (entry == null || expired) {
                    return "bad-txns-bid-not-found: name was never opened (or its auction already expired)";
                }
                if (state != 1) {
                    return "bad-txns-bid-wrong-state: name is " + stateName(state) + ", not BIDDING";
                }
            }
            case TxParser.COV_REVEAL -> {
                if (entry == null || expired) {
                    return "bad-txns-reveal-not-found: no active auction for this name";
                }
                if (state != 2) {
                    return "bad-txns-reveal-wrong-state: name is " + stateName(state) + ", not REVEAL";
                }
                // NOT checked here: that this REVEAL's value+nonce
                // actually hashes to the blind value committed in the
                // BID output it spends. See class comment.
            }
            case TxParser.COV_REGISTER -> {
                if (entry == null || expired) {
                    return "bad-txns-register-not-found: no closed auction for this name";
                }
                if (state != 3) {
                    return "bad-txns-register-wrong-state: name is " + stateName(state) + ", not CLOSED";
                }
                // NOT checked here: that the spending input is actually
                // the auction's winning REVEAL specifically. See class
                // comment -- Mempool's own signature check already
                // confirms whoever is spending genuinely controls that
                // UTXO, just not that it was the highest reveal.
            }
            case TxParser.COV_REDEEM -> {
                if (entry == null || expired) {
                    return "bad-txns-redeem-not-found: no closed auction for this name";
                }
                if (state != 3) {
                    return "bad-txns-redeem-wrong-state: name is " + stateName(state) + ", not CLOSED";
                }
            }
            case TxParser.COV_RENEW -> {
                if (entry == null || expired) {
                    return "bad-txns-renew-not-found: name is not registered";
                }
                if (state != 3 || !entry.registered) {
                    return "bad-txns-renew-not-registered: name is " + stateName(state)
                            + (entry.registered ? "" : " and not registered");
                }
            }
            case TxParser.COV_TRANSFER -> {
                if (entry == null || expired) {
                    return "bad-txns-transfer-not-found: name is not registered";
                }
                if (state != 3 || !entry.registered) {
                    return "bad-txns-transfer-not-registered: name is " + stateName(state)
                            + (entry.registered ? "" : " and not registered");
                }
                if (entry.transfer != 0) {
                    return "bad-txns-transfer-already-pending: a transfer is already pending on this name";
                }
            }
            case TxParser.COV_FINALIZE -> {
                if (entry == null || expired) {
                    return "bad-txns-finalize-not-found: name is not registered";
                }
                if (entry.transfer == 0) {
                    return "bad-txns-finalize-no-pending-transfer: no transfer is pending on this name";
                }
                if (mempoolHeight < entry.transfer + BlockProcessor.TRANSFER_LOCKUP) {
                    return "bad-txns-finalize-too-early: transfer lockup period has not elapsed ("
                            + (entry.transfer + BlockProcessor.TRANSFER_LOCKUP - mempoolHeight) + " blocks remaining)";
                }
            }
            case TxParser.COV_REVOKE -> {
                if (entry == null || expired) {
                    return "bad-txns-revoke-not-found: name is not registered";
                }
                if (state != 3) {
                    return "bad-txns-revoke-wrong-state: name is " + stateName(state) + ", not CLOSED";
                }
            }
            case TxParser.COV_UPDATE -> {
                if (entry == null || expired) {
                    return "bad-txns-update-not-found: name is not registered";
                }
                if (state != 3 || !entry.registered) {
                    return "bad-txns-update-not-registered: name is " + stateName(state)
                            + (entry.registered ? "" : " and not registered");
                }
            }
        }
        return null;
    }

    private static String stateName(int state) {
        return switch (state) {
            case 0 -> "OPENING";
            case 1 -> "BIDDING";
            case 2 -> "REVEAL";
            case 3 -> "CLOSED";
            case 4 -> "REVOKED";
            case 5 -> "LOCKED";
            default -> "UNKNOWN";
        };
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}