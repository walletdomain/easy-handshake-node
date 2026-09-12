package handshake.node;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * BlockProcessor — processes confirmed blocks to update the UTXO set
 * and name state in ChainDB.
 * <p>
 * Called by ChainSync for each new block as it is confirmed.
 * <p>
 * Processing steps for each block:
 *   1. Remove spent UTXOs (inputs)
 *   2. Add new UTXOs (outputs)
 *   3. Update name state for covenant outputs
 *   4. Evict confirmed transactions from mempool
 * <p>
 * Name state machine (from hsd/lib/covenants/rules.js):
 *   NONE    → OPEN      via OPEN covenant
 *   OPEN    → BID       via BID covenant
 *   BID     → REVEAL    via REVEAL covenant
 *   REVEAL  → REGISTER  via REGISTER covenant (auction winner)
 *   REVEAL  → REDEEM    via REDEEM covenant (auction losers)
 *   CLOSED  → UPDATE    via UPDATE covenant
 *   CLOSED  → RENEW     via RENEW covenant
 *   CLOSED  → TRANSFER  via TRANSFER covenant
 *   TRANSFER→ FINALIZE  via FINALIZE covenant (completes transfer)
 *   CLOSED  → REVOKE    via REVOKE covenant
 */
public class BlockProcessor {

    // Covenant types (matching TxParser constants)
    private static final int COV_NONE     = TxParser.COV_NONE;
    private static final int COV_CLAIM    = TxParser.COV_CLAIM;
    private static final int COV_OPEN     = TxParser.COV_OPEN;
    private static final int COV_BID      = TxParser.COV_BID;
    private static final int COV_REVEAL   = TxParser.COV_REVEAL;
    private static final int COV_REDEEM   = TxParser.COV_REDEEM;
    private static final int COV_REGISTER = TxParser.COV_REGISTER;
    private static final int COV_UPDATE   = TxParser.COV_UPDATE;
    private static final int COV_RENEW    = TxParser.COV_RENEW;
    private static final int COV_TRANSFER = TxParser.COV_TRANSFER;
    private static final int COV_FINALIZE = TxParser.COV_FINALIZE;
    private static final int COV_REVOKE   = TxParser.COV_REVOKE;

    // ── Signature verification depth cutoff ─────────────────────────────────
    // FIX: signature verification (pure CPU work, no shortcuts) was
    // confirmed as a major, unavoidable contributor to real, severe
    // processing slowdowns during the long initial catch-up sync --
    // directly measured, not assumed, via ScanCovenantVolume showing
    // genuinely extreme real transaction volume in several ranges of
    // the chain's history. A deliberate, explicit design decision: for
    // any block more than SIGNATURE_VERIFICATION_DEPTH behind the best
    // known peer height, skip signature verification entirely during
    // catch-up sync. This does NOT weaken header/proof-of-work
    // validation at all -- that runs in full, for every single header,
    // completely unaffected by this. The security property being
    // relied on: forging a chain SIGNATURE_VERIFICATION_DEPTH blocks
    // deep, with a transaction an honest miner would never have
    // included, requires sustained majority hashrate for that entire
    // depth -- genuinely difficult and expensive for a real attacker,
    // regardless of the exact depth chosen within a reasonable range.
    // 288 blocks (~2 days at Handshake's block time) was chosen as a
    // deliberately conservative depth for this reason specifically.
    public static final int SIGNATURE_VERIFICATION_DEPTH = 288;

    // Logged once, the first time full verification resumes after a
    // stretch of skipped blocks, so this behavior is visible rather
    // than a silent, invisible mode switch -- true only WHILE
    // currently skipping, so the transition back to full verification
    // gets exactly one clear log line, not one per block.
    private static boolean wasSkippingSignatures = false;

    // ── Per-phase timing diagnostics ────────────────────────────────────────
    // Direct measurement rather than inferring from GC log patterns: a
    // real, observed slowdown (down to ~2.7 seconds/block) persisted even
    // after fixing GC pause times with a larger heap, meaning something
    // OTHER than GC pausing itself is consuming the time. These
    // accumulate across blocks and get logged (then reset) every 100
    // blocks, matching ChainSync's own existing log cadence, so this
    // gives a direct breakdown of where time actually goes without
    // flooding the log with a line per block.
    private static long sigVerifyNanos = 0;
    private static long utxoBookkeepingNanos = 0;
    private static long covenantProcessingNanos = 0;
    // Split into its two constituent phases -- see
    // ChainDB.PersistTiming's own comment for why this distinction
    // matters: persist was consistently the dominant cost even in
    // windows with no logged background prune activity at all, and
    // the combined number alone couldn't say whether that was the
    // per-block write-new-nodes walk (persistBlockNanos) or the
    // commit/prune-submission step (maybeCommitNanos, which should be
    // near-instant now that the prune itself runs off-thread).
    private static long persistBlockNanos = 0;
    private static long maybeCommitNanos = 0;
    private static int blocksSinceTimingLog = 0;

    private static void logTimingIfDue(int height) {
        blocksSinceTimingLog++;
        if (blocksSinceTimingLog < 100) return;
        System.out.printf("[BlockProcessor] Timing over last %d blocks (ending height %d): "
                        + "sigVerify=%.1fs utxoBookkeeping=%.1fs covenantProcessing=%.1fs "
                        + "persistBlock=%.1fs maybeCommit=%.1fs heap=%s%n",
                blocksSinceTimingLog, height,
                sigVerifyNanos / 1e9, utxoBookkeepingNanos / 1e9, covenantProcessingNanos / 1e9,
                persistBlockNanos / 1e9, maybeCommitNanos / 1e9, UrkelNameTree.heapSnapshot());
        sigVerifyNanos = 0;
        utxoBookkeepingNanos = 0;
        covenantProcessingNanos = 0;
        persistBlockNanos = 0;
        maybeCommitNanos = 0;
        blocksSinceTimingLog = 0;
    }

    /**
     * Processes a raw block at the given height, updating UTXO set and
     * name state. Returns false if the block's merkle root doesn't match
     * its header (rejected outright -- no UTXO/name changes applied at
     * all -- since a peer sending mismatched transaction data alongside
     * an otherwise-valid header is exactly the scenario merkle
     * verification exists to catch, the same category as invalid PoW: a
     * signal an honest peer could never legitimately produce).
     */
    /** VALID: block fully, correctly applied -- safe to save and advance
     *  the tip past. REJECTED: a genuine consensus violation (bad
     *  merkle root, failed signature) -- the peer that sent this is at
     *  fault and should be banned. INTERNAL_ERROR: something in OUR OWN
     *  processing broke (a bug, a storage error) that has nothing to do
     *  with what the peer actually sent -- must not advance the tip
     *  past it (this height needs to be retried, not silently treated
     *  as done), but banning the peer over our own bug would be wrong
     *  and could end up banning every peer we ever sync from if the
     *  same internal issue recurs. Previously this whole distinction
     *  didn't exist: process() returned a single boolean that meant
     *  "advance the tip" and nothing else, so an unexpected internal
     *  exception was either (a) silently treated as fully valid (the
     *  original bug) or (b) indistinguishable from a real peer-fault
     *  rejection (a smaller, but still real, follow-on problem). */
    public enum Result { VALID, REJECTED, INTERNAL_ERROR }

    public static Result process(byte[] rawBlock, int height,
                                 ChainDB db, Mempool mempool, int bestKnownPeerHeight) {
        try {
            return processInternal(rawBlock, height, db, mempool, bestKnownPeerHeight)
                    ? Result.VALID : Result.REJECTED;
        } catch (Exception e) {
            // Confirmed via a real, observed "Chunk ... not found"
            // MVStore error landing exactly on 36-block tree-commit
            // boundaries (the one place persistNameTreeState()'s new
            // node-store pruning runs) -- an exception THERE means the
            // tree's on-disk state may be incomplete or inconsistent
            // for this height. This is categorically an internal
            // failure, not evidence the peer sent us anything invalid.
            System.err.printf("[BlockProcessor] Internal error at height %d: %s -- "
                    + "NOT advancing past it (will be retried), and NOT blaming "
                    + "whichever peer happened to send it%n", height, e.getMessage());
            return Result.INTERNAL_ERROR;
        }
    }

    private static boolean processInternal(byte[] rawBlock, int height,
                                           ChainDB db, Mempool mempool, int bestKnownPeerHeight) {
        // Parse the block
        List<TxParser.ParsedTx> txs = parseBlockTxs(rawBlock);
        List<String> confirmedTxids = new ArrayList<>();

        // Merkle root verification: proves the actual transactions in
        // this block correspond to what the (already header-validated)
        // header committed to via its merkleRoot field. Header validation
        // alone only proves the HEADER is legitimate -- it says nothing
        // about whether the accompanying transaction data is genuine.
        // Now blocking (upgraded from an earlier warn-only phase): both
        // the merkle algorithm itself and a real underlying transaction-
        // parsing bug (a varint misread that corrupted parsing for any
        // transaction with 253+ inputs/outputs/witness items) have been
        // rigorously verified against real captured block data, including
        // a full end-to-end match through this exact code path.
        List<byte[]> txidBytes = new ArrayList<>();
        for (TxParser.ParsedTx tx : txs) {
            byte[] base = Arrays.copyOf(tx.raw, tx.baseSize);
            txidBytes.add(Blake2b.hash256(base));
        }
        byte[] headerBytes = Arrays.copyOf(rawBlock, Math.min(236, rawBlock.length));
        byte[] claimedMerkleRoot = HeaderUtil.merkleRoot(headerBytes);
        if (!MerkleUtil.verify(txidBytes, claimedMerkleRoot)) {
            System.err.printf("[BlockProcessor] Merkle root mismatch at height %d "
                    + "-- rejecting block, no UTXO/name changes applied%n", height);
            return false;
        }

        // Urkel tree root verification -- the actual validation gap this
        // whole tree effort exists to close. A header at height H always
        // commits to the tree's committed root as of the last interval
        // boundary strictly BEFORE H (confirmed from chain.js/chaindb.js:
        // the commit for a boundary height only takes effect for headers
        // AFTER it, never that boundary block's own header) -- so this
        // must run here, before this block's own covenants get applied
        // and before persistNameTreeState() below might advance the
        // committed root itself, comparing against whatever the last
        // commit already established.
        //
        // Warn-only for now, not a hard rejection -- unlike the merkle
        // check above (which earned blocking status only after being
        // rigorously verified across real captured block data), this
        // specific check has only been spot-verified against one name at
        // one height so far, not proven across a wide range of real
        // commit boundaries yet. Matches this project's own established
        // pattern of starting new validation warn-only and upgrading to
        // blocking once it's held up over more of the real chain.
        byte[] claimedTreeRoot = HeaderUtil.treeRoot(headerBytes);
        byte[] ourCommittedRoot = db.getNameTree().committedRoot();
        if (!Arrays.equals(claimedTreeRoot, ourCommittedRoot)) {
            System.err.printf("[BlockProcessor] *** URKEL TREE ROOT MISMATCH at height %d *** "
                            + "header claims %s, we computed %s -- name/covenant data may be silently "
                            + "wrong from this point forward. Not rejecting the block yet (warn-only "
                            + "phase), but this needs investigating.%n",
                    height, hex(claimedTreeRoot), hex(ourCommittedRoot));
        }

        for (TxParser.ParsedTx tx : txs) {
            String txid = TxParser.computeTxid(tx.raw);
            if (txid == null) continue;
            confirmedTxids.add(txid);

            // Signature verification happens OUTSIDE the per-transaction
            // try/catch below, deliberately: a covenant-parsing bug in
            // OUR OWN code isolating to one transaction is a very
            // different thing from a transaction whose signature we
            // actually checked and found invalid -- the latter is a real
            // consensus violation and must reject the entire block, not
            // just be logged and skipped like the former. Only a
            // definite, checked failure rejects; a UTXO we can't find or
            // an address type TxVerify doesn't yet support (e.g.
            // 32-byte scripthash/multisig, which are legitimate and
            // exist on real mainnet) is left unverified rather than
            // treated as invalid -- rejecting those would break sync on
            // perfectly valid, real blocks that every other real hsd
            // validator accepts.
            if (!tx.inputs.isEmpty() && !tx.inputs.get(0).isCoinbase()) {
                // FIX: skip signature verification entirely for blocks
                // deep enough behind the best known peer height -- see
                // SIGNATURE_VERIFICATION_DEPTH's own comment for the
                // full reasoning. bestKnownPeerHeight <= 0 means "not
                // yet known" (e.g. before any peer connection has been
                // established) -- deliberately defaults to full
                // verification in that case, not skipping, since
                // treating an unknown height as "definitely far enough
                // behind" would be a real, dangerous bug (skipping
                // verification on the very blocks at the tip, which is
                // exactly the opposite of the intent here).
                boolean tooFarBehindToSkip =
                        bestKnownPeerHeight > 0 && (bestKnownPeerHeight - height) > SIGNATURE_VERIFICATION_DEPTH;
                if (tooFarBehindToSkip) {
                    if (!wasSkippingSignatures) {
                        System.out.printf("[BlockProcessor] Height %d is more than %d blocks behind "
                                        + "the best known peer height (%d) -- skipping signature verification "
                                        + "for this and subsequent blocks until caught up%n",
                                height, SIGNATURE_VERIFICATION_DEPTH, bestKnownPeerHeight);
                        wasSkippingSignatures = true;
                    }
                } else {
                    if (wasSkippingSignatures) {
                        System.out.printf("[BlockProcessor] Height %d is now within %d blocks of the "
                                        + "best known peer height (%d) -- resuming full signature verification%n",
                                height, SIGNATURE_VERIFICATION_DEPTH, bestKnownPeerHeight);
                        wasSkippingSignatures = false;
                    }
                    long sigStart = System.nanoTime();
                    for (int i = 0; i < tx.inputs.size(); i++) {
                        TxParser.Input input = tx.inputs.get(i);
                        ChainDB.UtxoEntry spentUtxo = db.getUtxo(input.prevTxid, input.prevIndex);
                        if (spentUtxo == null || spentUtxo.addrHash().length != 20) {
                            continue; // unverifiable -- not a failure, just not checked
                        }
                        if (!TxVerify.verifyInput(tx, i, spentUtxo.addrHash(), spentUtxo.value())) {
                            System.err.printf("[BlockProcessor] Signature verification failed for "
                                    + "tx %s input %d at height %d -- rejecting block, no UTXO/name "
                                    + "changes applied%n", txid, i, height);
                            return false;
                        }
                    }
                    sigVerifyNanos += System.nanoTime() - sigStart;
                }
            }

            // Isolated per-transaction: previously an exception in ANY
            // single transaction's covenant processing would propagate
            // all the way out of processInternal() and abort the ENTIRE
            // block, discarding every other transaction's UTXO and
            // name-state updates too -- not just the failing one's. A
            // problem with one transaction's covenant data shouldn't cost
            // the rest of a perfectly valid block.
            try {
                long utxoStart = System.nanoTime();
                // Step 1: Remove spent UTXOs
                if (!tx.inputs.isEmpty() && !tx.inputs.get(0).isCoinbase()) {
                    for (TxParser.Input input : tx.inputs) {
                        db.removeUtxo(input.prevTxid, input.prevIndex);
                    }
                }

                // Step 2: Add new UTXOs and process covenants
                for (int i = 0; i < tx.outputs.size(); i++) {
                    TxParser.Output out = tx.outputs.get(i);

                    // Add UTXO
                    byte[] covData = serializeCovenant(out.covenant);
                    ChainDB.UtxoEntry utxo = new ChainDB.UtxoEntry(
                            out.value,
                            out.addrVersion,
                            out.addrHash,
                            out.covenant != null ? out.covenant.type : 0,
                            covData,
                            tx.inputs.isEmpty() || tx.inputs.get(0).isCoinbase(),
                            height
                    );
                    db.saveUtxo(txid, i, utxo);
                    utxoBookkeepingNanos += System.nanoTime() - utxoStart;

                    // Step 3: Update name state for covenant outputs --
                    // timed SEPARATELY from raw UTXO bookkeeping above,
                    // specifically because this is what actually
                    // touches the live, in-memory Urkel tree
                    // (insert()/remove() per name), which may need to
                    // resolve() Hash placeholders for parts of the tree
                    // this run hasn't touched yet since the last
                    // restart -- a real, different cost than simple
                    // UTXO map reads/writes, and one worth being able
                    // to see on its own rather than folded into a
                    // single combined number.
                    if (out.covenant != null && out.covenant.type != COV_NONE) {
                        long covenantStart = System.nanoTime();
                        processNameCovenant(out, txid, i, height, db);
                        covenantProcessingNanos += System.nanoTime() - covenantStart;
                    }
                    utxoStart = System.nanoTime();
                }
            } catch (Exception e) {
                System.err.printf("[BlockProcessor] Error processing tx %s at height %d: %s "
                        + "(rest of block still processed)%n", txid, height, e.getMessage());
            }
        }

        // Step 3a: Flush this block's buffered name writes as a single
        // batched operation -- see ChainDB.saveName()/flushPendingNames()'s
        // own comments for the full reasoning. Timed as part of
        // persistBlock, since it's the same kind of operation:
        // flushing this block's accumulated writes once, rather than
        // individually as they happened.
        long nameFlushStart = System.nanoTime();
        db.flushPendingNames();
        persistBlockNanos += System.nanoTime() - nameFlushStart;

        // Step 3b: Persist any new tree nodes from this block, then
        // advance the "official" committed root if this height lands
        // on a real interval boundary -- confirmed directly from
        // chain.js/chaindb.js. Must run once per block (not per
        // covenant/transaction), after every covenant in this block
        // has already been applied above. Persisting every block, not
        // just at commit boundaries, is required for correctness
        // across a restart (see UrkelNameTree's own class comment).
        ChainDB.PersistTiming timing = db.persistNameTreeStateTimed(height, bestKnownPeerHeight);
        persistBlockNanos += timing.persistBlockNanos();
        maybeCommitNanos += timing.maybeCommitNanos();
        logTimingIfDue(height);

        // Step 4: Evict confirmed transactions from mempool
        if (mempool != null) {
            mempool.onBlockConnected(confirmedTxids);
        }

        // NOTE: no db.commit() here anymore -- this used to commit after
        // EVERY single block, unbatched, unlike header sync (which
        // commits once per batch of up to 2000). As the database grows
        // with real block/UTXO/name data, each individual disk commit
        // gets progressively more expensive, producing a gradually
        // worsening slowdown with no error and no socket timeout (since
        // it's not actually blocked on network I/O) -- which looks
        // exactly like an unexplained hang. The caller now batches
        // commits instead, matching the header-sync pattern.
        return true;
    }

    // ── Expiration ───────────────────────────────────────────────────────────
    // Mirrors namestate.js's state()/isExpired()/maybeExpire() exactly.
    // Mainnet timing constants, confirmed from networks.js:
    private static final int TREE_INTERVAL_CONST = 36;
    private static final int OPEN_PERIOD = TREE_INTERVAL_CONST + 1;     // 37
    private static final int BIDDING_PERIOD = 5 * 144;                  // 720
    private static final int REVEAL_PERIOD = 10 * 144;                  // 1440
    private static final int RENEWAL_WINDOW = 2 * 365 * 144;            // 105120
    private static final int AUCTION_MATURITY = (5 + 10 + 14) * 144;    // 4176
    private static final int LOCKUP_PERIOD = 30 * 144;                  // 4320

    /** 0=OPENING,1=BIDDING,2=REVEAL,3=CLOSED,4=REVOKED,5=LOCKED */
    private static int computeState(ChainDB.NameEntry e, int height) {
        if (e.revoked != 0) return 4; // REVOKED
        if (e.claimed != 0) return (height < e.height + LOCKUP_PERIOD) ? 5 : 3; // LOCKED : CLOSED
        if (height < e.height + OPEN_PERIOD) return 0; // OPENING
        if (height < e.height + OPEN_PERIOD + BIDDING_PERIOD) return 1; // BIDDING
        if (height < e.height + OPEN_PERIOD + BIDDING_PERIOD + REVEAL_PERIOD) return 2; // REVEAL
        return 3; // CLOSED
    }

    private static boolean isExpired(ChainDB.NameEntry e, int height) {
        if (e.revoked != 0) {
            return height >= e.revoked + AUCTION_MATURITY;
        }
        // Can only expire once CLOSED.
        if (computeState(e, height) != 3) return false;
        // Claimed names can't expire during the claim period -- for
        // non-reserved names (the overwhelming majority processed so
        // far) claimed is always 0, so isClaimable is always false and
        // this check is a no-op; not fully implementing the claimPeriod
        // side of isClaimable here since no claimed-and-still-in-period
        // name has been observed diverging yet.
        if (e.claimed != 0) return false;
        // Two years with no renewal -- start over.
        if (height >= e.renewal + RENEWAL_WINDOW) return true;
        // Nobody ever revealed a bid -- start over.
        if (e.ownerTxid == null || e.ownerTxid.isEmpty()) return true;
        return false;
    }

    /** Matches real hsd's ns.maybeExpire(height, network) exactly --
     * called on every single covenant touch, before any type-specific
     * handling, confirmed directly from chain.js's verifyCovenants. */
    private static void maybeExpire(ChainDB.NameEntry e, int height) {
        if (isExpired(e, height)) {
            byte[] preservedData = e.resourceData; // reset() preserves data, confirmed from namestate.js's maybeExpire()
            e.height = height;
            e.renewal = height;
            e.ownerTxid = null;
            e.ownerIndex = 0;
            e.value = 0;
            e.highest = 0;
            e.transfer = 0;
            e.revoked = 0;
            e.claimed = 0;
            e.renewals = 0;
            e.registered = false;
            e.weak = false;
            e.resourceData = preservedData;
            e.expired = true;
        }
    }

    // ── Name state machine ────────────────────────────────────────────────────

    private static void processNameCovenant(TxParser.Output out, String txid,
                                            int outputIndex, int height, ChainDB db) {
        int type = out.covenant.type;
        List<TxParser.CovenantItem> items = out.covenant.items;
        if (items.isEmpty()) return;

        // Get name hash (item[0] for all covenant types)
        byte[] nameHashBytes = items.get(0).data;
        if (nameHashBytes == null || nameHashBytes.length != 32) return;
        String nameHash = hex(nameHashBytes);

        // Get or create name entry
        ChainDB.NameEntry entry = db.getNameByHash(nameHash);
        if (entry == null) {
            entry = new ChainDB.NameEntry();
            entry.nameHash = nameHash;
            entry.name = extractName(items, type);
            // FIX: mirrors real hsd's `if (ns.isNull()) { ns.set(name,
            // height); }`, which runs BEFORE maybeExpire() -- confirmed
            // directly from chain.js. Without this, a brand-new entry's
            // default height=0 would make computeState() below see it
            // as having been open since block 0, i.e. CLOSED for
            // essentially any real height, and isExpired() would then
            // incorrectly mark every first-ever touch of a name as
            // expired. The type-specific switch below still re-sets
            // height/renewal for OPEN/CLAIM to the same value, so this
            // is redundant-but-harmless for those, and never reached
            // for other types in valid data (real hsd throws
            // 'Database inconsistency' in that case).
            entry.height = height;
            entry.renewal = height;
        }

        // FIX: real hsd calls ns.maybeExpire(height, network) on EVERY
        // covenant touch, before any type-specific handling -- confirmed
        // directly from chain.js's verifyCovenants, right after the
        // ns.isNull() -> ns.set() branch and before computing state.
        // This was a known, documented gap (UrkelNameState.expired was
        // wired up for encoding but nothing ever set it). Root-caused
        // via a real name ("considinestokes") that opened at height
        // 2852, got zero bids, and was opened again at height 5809 --
        // real hsd's getnameproof shows expired=true (field bit 8) at
        // that point, which nothing in this validator was producing.
        maybeExpire(entry, height);

        // Update owner outpoint -- but NOT for OPEN or BID: confirmed
        // directly against real hsd's own getnameproof output (for
        // "sad" at the exact height in question) that a fresh open has
        // NO owner at all (field byte 0000, not 0100) -- real hsd's
        // ns.set(name, height) -> reset() explicitly nulls owner on a
        // fresh open, and BID never mutates NameState at all (confirmed
        // earlier from chaindb.js's own comment). Previously this was
        // unconditional, incorrectly stamping the CURRENT transaction's
        // own txid as "owner" even during OPEN -- a real, confirmed bug
        // affecting every single name ever opened, not a
        // hasRollout/timing issue as earlier hypothesized.
        // FIX: REDEEM and REVOKE also never call setOwner() in real
        // hsd -- confirmed directly from chain.js (REDEEM is the
        // LOSING bidder reclaiming funds, unrelated to who owns the
        // name; REVOKE only sets revoked/transfer/data). Previously
        // both fell through to this unconditional assignment, which
        // would incorrectly overwrite the real owner with whichever
        // REDEEM or REVOKE transaction happened to be processed --
        // REDEEM alone occurred 162 times in a single 36-block window
        // in real chain data, making this a significant, frequent bug.
        if (type != COV_OPEN && type != COV_BID && type != COV_REVEAL
                && type != COV_REDEEM && type != COV_REVOKE) {
            entry.ownerTxid  = txid;
            entry.ownerIndex = outputIndex;
        }

        // Apply state transition
        switch (type) {
            case COV_OPEN -> {
                entry.state   = "OPENING";
                entry.height  = height;
                // Matches real hsd's ns.set(name, height) -> reset(height),
                // which sets BOTH height and renewal together on a fresh
                // open, confirmed directly from namestate.js -- previously
                // missing here, which would have produced a NameState that
                // encodes differently (and therefore hashes differently)
                // from what real hsd actually commits to the tree.
                entry.renewal = height;
                entry.name    = extractName(items, type);
            }
            case COV_BID -> {
                entry.state  = "BIDDING";
            }
            case COV_REVEAL -> {
                entry.state  = "REVEAL";
                // Matches real hsd's exact "track top-2" reveal logic
                // (Vickrey/second-price auction), confirmed directly
                // from chain.js -- previously this just overwrote
                // entry.value with whatever reveal happened to be
                // processed last, and never set owner conditionally on
                // being the current highest bidder at all (owner was
                // set unconditionally, before this switch, to whichever
                // reveal transaction was processed last -- wrong
                // whenever more than one bidder reveals for the same
                // name, which real auctions with decoy bids do
                // constantly).
                boolean ownerIsNull = entry.ownerTxid == null || entry.ownerTxid.isEmpty();
                if (ownerIsNull || out.value > entry.highest) {
                    entry.value      = entry.highest;
                    entry.ownerTxid  = txid;
                    entry.ownerIndex = outputIndex;
                    entry.highest    = out.value;
                } else if (out.value > entry.value) {
                    entry.value = out.value;
                }
            }
            case COV_REDEEM -> {
                // Losing bid — no state change to name, just UTXO freed
            }
            case COV_REGISTER -> {
                entry.state   = "CLOSED";
                // FIX: real hsd's REGISTER never calls setHeight() or
                // setValue() at all -- confirmed directly from chain.js.
                // Both should already match (height==start, value==the
                // second-highest bid from REVEAL) since real consensus
                // rules require it, but this code doesn't actually
                // validate that -- previously overwriting them here
                // would silently paper over an earlier bug instead of
                // preserving the real, already-correct values.
                entry.registered = true;
                // FIX: real hsd's REGISTER DOES call setRenewal(height)
                // as its final step -- confirmed directly from chain.js.
                // This one belongs, unlike height/value above.
                entry.renewal = height;
                // FIX: matches real hsd's `if (data.length > 0)
                // ns.setData(data)` -- previously missing the length
                // check, same class of bug as UPDATE had.
                if (items.size() > 2 && items.get(2).data != null && items.get(2).data.length > 0) {
                    entry.resourceData = items.get(2).data;
                }
            }
            case COV_CLAIM -> {
                entry.state   = "CLOSED";
                // FIX: real hsd's ns.setHeight(height) uses the actual
                // current processing height, NOT covenant-supplied data
                // -- confirmed from chain.js's claim handling. Previously
                // read extractU32(items, 1), which happened to coincide
                // with the real height for this specific transaction but
                // isn't guaranteed to in general.
                entry.height  = height;
                entry.renewal = height;
                // FIX: real hsd's ns.setValue(0) ALWAYS zeroes value for
                // claims, regardless of the transaction's own output
                // value -- confirmed directly from chain.js. Previously
                // used out.value, which for a real claim transaction
                // (503436887) produced a completely different encoded
                // NameState than real hsd's, hashing differently and
                // diverging the tree -- this was the actual root cause
                // of the height-2377 divergence.
                entry.value   = 0;
                // FIX: item[4] is a 32-byte block-hash commitment, not a
                // U32 -- the actual claimed-height field real hsd reads
                // (covenant.getU32(5), verified against
                // getMainHeight(item[4])) is item[5]. Previously read
                // item[4] as a U32, which for this real transaction
                // (whose hash happens to start with 0x00000000) silently
                // produced 0 instead of the real value.
                entry.claimed = extractU32(items, 5);
                // FIX: weak flag was never captured at all -- real hsd's
                // ns.setWeak(weak) comes from (covenant.getU8(3) & 1).
                if (items.size() > 3 && items.get(3).data != null && items.get(3).data.length > 0) {
                    entry.weak = (items.get(3).data[0] & 1) != 0;
                }
                // NOT extracting resourceData here -- CLAIM's covenant
                // structure (DNSSEC-based legacy name claims) isn't
                // confirmed to carry record data at the same item index
                // as a normal REGISTER, and guessing wrong here would
                // silently store garbage as "DNS records" for claimed
                // names.
            }
            case COV_UPDATE -> {
                entry.state = "CLOSED";
                // FIX: real hsd's UPDATE case never calls setRenewal() at
                // all -- confirmed directly from chain.js. Previously set
                // entry.renewal = height unconditionally here, which
                // would incorrectly extend a name's renewal/expiration
                // window on every single update, not just on an actual
                // RENEW/REGISTER/FINALIZE.
                if (items.size() > 2 && items.get(2).data != null && items.get(2).data.length > 0) {
                    // FIX: real hsd only calls setData() when
                    // data.length > 0 -- an update with empty data
                    // leaves existing resourceData untouched, it does
                    // NOT clear it. Previously this overwrote
                    // resourceData with an empty array whenever an
                    // update happened to carry no data.
                    entry.resourceData = items.get(2).data;
                }
                // FIX: real hsd's ns.setTransfer(0) explicitly cancels
                // any pending transfer on every update -- previously
                // missing entirely, leaving a stale nonzero transfer
                // value (which affects the encoded field bitmap) after
                // an update that should have cleared it.
                entry.transfer = 0;
            }
            case COV_RENEW -> {
                entry.state   = "CLOSED";
                entry.renewal = height;
                entry.renewals++;
                // FIX: real hsd's RENEW also calls setTransfer(0) --
                // confirmed directly from chain.js. Previously missing,
                // same class of bug as UPDATE had: a stale pending
                // transfer would survive a renewal untouched.
                entry.transfer = 0;
            }
            case COV_TRANSFER -> {
                entry.state    = "CLOSED"; // still CLOSED but transfer pending
                entry.transfer = height;
            }
            case COV_FINALIZE -> {
                entry.state    = "CLOSED";
                entry.transfer = 0;        // transfer complete
                entry.renewal  = height;
                // FIX: real hsd's ns.setRenewals(ns.renewals + 1)
                // INCREMENTS the existing count -- confirmed directly
                // from chain.js. item[5] is only a verification copy of
                // the PRE-transfer renewals count (checked against
                // ns.renewals to ensure a transfer didn't sneak in a
                // change), not the new value -- previously this
                // overwrote renewals with that old, unincremented copy
                // instead of bumping it.
                entry.renewals = entry.renewals + 1;
                // FIX: real hsd's FINALIZE only VALIDATES that item[4]
                // matches ns.claimed, it never calls setClaimed() --
                // confirmed directly from chain.js. Removed the
                // overwrite, same reasoning as REGISTER's height/value.
            }
            case COV_REVOKE -> {
                entry.state   = "REVOKED";
                entry.revoked = height;
                entry.transfer = 0;
                // FIX: real hsd's ns.setData(null) clears any existing
                // DNS record data on revocation -- confirmed directly
                // from chain.js. Previously missing entirely, leaving
                // stale resourceData behind on a revoked name.
                entry.resourceData = new byte[0];
            }
        }

        db.saveName(entry);

        // Feed the tree, matching real hsd's own exclusion exactly:
        // "BID and REDEEM covenants do not update NameState" (confirmed
        // directly from chaindb.js's comment). Every other covenant
        // type does, mirroring the state transitions already applied
        // to `entry` above.
        // Feed the tree, matching real hsd's own exclusion -- confirmed
        // directly from chaindb.js's comment for BID/REDEEM, and now
        // ALSO confirmed empirically for OPEN: a real, synced mainnet
        // header at height 2052 claimed an all-zero (completely empty)
        // treeRoot despite many real OPEN transactions having already
        // occurred by that point -- meaning OPEN genuinely does not
        // cause a tree insertion on the real network either, even
        // though it does mutate an in-memory NameState during
        // covenant verification (confirmed from chain.js's own
        // verifyCovenants). The exact JS mechanism that keeps this
        // transient OPEN-time mutation from reaching the committed
        // tree wasn't fully traced through chain.js/chaindb.js's control
        // flow with full confidence -- this exclusion is based on
        // direct empirical confirmation (FindFirstDivergence showing
        // zero divergence once OPEN is excluded here), not a fully
        // understood source-level explanation. Worth revisiting if a
        // deeper read of chaindb.js's connect path later clarifies the
        // real mechanism.
        if (type != COV_BID && type != COV_REDEEM) {
            UrkelNameState ns = new UrkelNameState();
            ns.name = entry.name != null ? entry.name.getBytes(java.nio.charset.StandardCharsets.US_ASCII) : new byte[0];
            ns.data = entry.resourceData != null ? entry.resourceData : new byte[0];
            ns.height = entry.height;
            ns.renewal = entry.renewal;
            if (entry.ownerTxid != null && !entry.ownerTxid.isEmpty()) {
                ns.ownerHash = fromHex(entry.ownerTxid);
                ns.ownerIndex = entry.ownerIndex;
            }
            ns.value = entry.value;
            ns.highest = entry.highest;
            ns.transfer = entry.transfer;
            ns.revoked = entry.revoked;
            ns.claimed = entry.claimed;
            ns.renewals = entry.renewals;
            ns.registered = entry.registered;
            ns.expired = entry.expired; // FIX: previously hardcoded false regardless of entry state -- see maybeExpire()
            ns.weak = entry.weak;

            db.getNameTree().applyNameState(nameHashBytes, ns);
        }
    }

    // ── Block parsing ─────────────────────────────────────────────────────────

    /**
     * Parses transactions from a raw block.
     * Block format: header(236) + tx_count(varint) + txs[]
     */
    public static List<TxParser.ParsedTx> parseBlockTxs(byte[] rawBlock) {
        List<TxParser.ParsedTx> txs = new ArrayList<>();
        try {
            int pos = 236; // skip header
            if (pos >= rawBlock.length) return txs;

            // Read tx count (varint)
            int txCount = rawBlock[pos] & 0xFF;
            if (txCount < 0xFD) {
                pos++;
            } else if (txCount == 0xFD) {
                txCount = ((rawBlock[pos+1] & 0xFF) | ((rawBlock[pos+2] & 0xFF) << 8));
                pos += 3;
            } else {
                pos += 5; // skip 0xFE + 4 bytes
            }

            // Parse each transaction
            for (int i = 0; i < txCount && pos < rawBlock.length; i++) {
                byte[] remaining = Arrays.copyOfRange(rawBlock, pos, rawBlock.length);
                TxParser.ParsedTx tx = TxParser.parse(remaining);
                if (tx == null) break;
                txs.add(tx);
                // Advance past the full transaction, INCLUDING witness
                // data. tx.totalSize is now genuinely computed by walking
                // the real witness stacks (see TxParser.parse()) --
                // previously this called a separate function that just
                // guessed "baseSize + 150 bytes per input" with no
                // relationship to the actual witness data, silently
                // misaligning every transaction after any one whose real
                // witness size didn't match that guess.
                pos += tx.totalSize;
            }
        } catch (Exception e) {
            System.err.println("[BlockProcessor] Block parse error: " + e.getMessage());
        }
        return txs;
    }

    /**
     * Estimates the full transaction size including witnesses.
     * Falls back to baseSize + reasonable witness estimate.
     */
    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Extracts the plaintext name string from a covenant's items, when
     * that covenant type actually carries one at item index 2. Confirmed
     * against a real, complete covenant item reference for every type:
     * <p>
     *   CLAIM:    [nameHash, height, name, flags]
     *   OPEN:     [nameHash, height, name]
     *   BID:      [nameHash, height, name, blind]
     *   FINALIZE: [nameHash, height, name, flags, claimHeight, renewals, blockHash]
     * <p>
     *   REVEAL:   [nameHash, height, nonce]        -- item[2] is a NONCE, not a name
     *   REDEEM:   [nameHash, height]                -- no item[2] at all
     *   REGISTER: [nameHash, height, recordData, blockHash]
     *   UPDATE:   [nameHash, height, recordData]
     *   RENEW:    [nameHash, height, blockHash]
     *   TRANSFER: [nameHash, height, version, address]
     *   REVOKE:   [nameHash, height]                -- no item[2] at all
     * <p>
     * Previously EVERY one of these second-group types was treated as if
     * item[2] held the name, meaning random binary data (nonces, hashes,
     * record data) was being interpreted as ASCII text and stored as the
     * name. For 32 random bytes, there's roughly a 12% chance per call
     * of that data containing a literal '|' byte, which corrupts the
     * pipe-delimited NameEntry record for all future reads -- exactly
     * the recurring "unparseable NameEntry" warnings seen in testing.
     * COV_CLAIM was also missing from this entirely, silently leaving
     * claimed names without a name string at all.
     */
    private static String extractName(List<TxParser.CovenantItem> items, int type) {
        int nameIndex = switch (type) {
            case COV_CLAIM, COV_OPEN, COV_BID, COV_FINALIZE -> 2;
            default -> -1; // this covenant type doesn't carry a name at item[2]
        };
        if (nameIndex < 0 || nameIndex >= items.size()) return "";
        byte[] nameBytes = items.get(nameIndex).data;
        if (nameBytes == null) return "";
        return new String(nameBytes, StandardCharsets.US_ASCII);
    }

    private static int extractU32(List<TxParser.CovenantItem> items, int index) {
        if (index >= items.size()) return 0;
        byte[] b = items.get(index).data;
        if (b == null || b.length < 4) return 0;
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8)
                | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
    }

    private static byte[] serializeCovenant(TxParser.Covenant cov) {
        if (cov == null || cov.items.isEmpty()) return new byte[0];
        // Simple serialization: concatenate all items with length prefixes
        int totalLen = 0;
        for (TxParser.CovenantItem item : cov.items) {
            totalLen += 1 + (item.data != null ? item.data.length : 0);
        }
        byte[] result = new byte[totalLen];
        int pos = 0;
        for (TxParser.CovenantItem item : cov.items) {
            int len = item.data != null ? item.data.length : 0;
            result[pos++] = (byte) len;
            if (item.data != null) {
                System.arraycopy(item.data, 0, result, pos, len);
                pos += len;
            }
        }
        return result;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] fromHex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }
}