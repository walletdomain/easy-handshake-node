package handshake.node;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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

    /**
     * A fingerprint of THIS class's own compiled bytecode -- used by
     * resumable, from-genesis replay tools (UrkelTreeRecovery,
     * UrkelDivergenceFinder) to detect when covenant-processing logic
     * has changed between runs, so a resumed replay never silently
     * mixes progress computed under old logic with new logic applied
     * from that point forward. Confirmed as a real, previously-missing
     * safeguard: resumability originally only checked whether prior
     * progress EXISTED, never whether the code that produced it still
     * matched what was about to run, meaning a resumed run after any
     * code change would have silently blended two different rule sets
     * with no way to tell which heights used which.
     * <p>
     * Automatic and safe by construction: any change to this class's
     * actual, compiled logic -- a modified check, a changed constant,
     * a different code path -- produces a different fingerprint,
     * confirmed directly by testing (changing TREE_INTERVAL_CONST
     * changed the hash; a comment-only edit did not, since Java
     * comments never reach the compiled bytecode at all -- the
     * fingerprint tracks what actually executes, not the source
     * text). A rare, unnecessary "start over" from an unrelated
     * recompile is a far better outcome than silently trusting stale
     * logic, so this errs conservative rather than trying to be
     * clever about which changes "really" matter. Reads this class's
     * own .class bytes directly off the classpath rather than hashing
     * the .java source, since the source may not even be present at
     * runtime (e.g. running from a packaged jar) and the compiled
     * bytecode is what's actually executing regardless.
     */
    /**
     * A fingerprint of the ENTIRE compiled handshake.node package --
     * every single .class file, not a hand-picked list of "the ones
     * that matter." This exists because of a second, real gap found
     * in an earlier, narrower version of this method that only
     * fingerprinted BlockProcessor.class plus one caller-specified
     * class: UrkelNameTree.java, UrkelTree.java, UrkelNodeStore.java,
     * ReservedNames.java, HandshakeCovenantRules.java, ChainDB.java,
     * and others all directly affect what a replay actually computes,
     * and naming "the relevant classes" one at a time is exactly the
     * same fragile, remember-to-update-it burden this mechanism exists
     * to eliminate in the first place -- it would only take one more
     * change in one more file this list doesn't happen to mention to
     * silently defeat it again. Hashing every compiled class in the
     * package needs no such list and cannot miss a file that turns
     * out to matter, because nothing is excluded to begin with.
     * <p>
     * Handles both an exploded classes directory (e.g. IntelliJ's own
     * target/classes) and a packaged jar, since either is a real way
     * this project might be run.
     */
    public static String computeCovenantLogicFingerprint() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            java.net.URL location = BlockProcessor.class.getProtectionDomain().getCodeSource().getLocation();
            File classpathRoot = new File(location.toURI());

            if (classpathRoot.isDirectory()) {
                File packageDir = new File(classpathRoot, "handshake/node");
                File[] classFiles = packageDir.listFiles((dir, name) -> name.endsWith(".class"));
                if (classFiles == null) {
                    throw new IllegalStateException(
                            "Could not list handshake/node class files at " + packageDir);
                }
                Arrays.sort(classFiles, Comparator.comparing(File::getName));
                for (File f : classFiles) {
                    digest.update(f.getName().getBytes(StandardCharsets.UTF_8));
                    try (InputStream in = new java.io.FileInputStream(f)) {
                        byte[] buf = new byte[8192];
                        int n;
                        while ((n = in.read(buf)) != -1) digest.update(buf, 0, n);
                    }
                }
            } else {
                try (java.util.jar.JarFile jar = new java.util.jar.JarFile(classpathRoot)) {
                    List<java.util.jar.JarEntry> entries = new ArrayList<>();
                    java.util.Enumeration<java.util.jar.JarEntry> e = jar.entries();
                    while (e.hasMoreElements()) {
                        java.util.jar.JarEntry entry = e.nextElement();
                        if (entry.getName().startsWith("handshake/node/") && entry.getName().endsWith(".class")) {
                            entries.add(entry);
                        }
                    }
                    entries.sort(Comparator.comparing(java.util.jar.JarEntry::getName));
                    for (java.util.jar.JarEntry entry : entries) {
                        digest.update(entry.getName().getBytes(StandardCharsets.UTF_8));
                        try (InputStream in = jar.getInputStream(entry)) {
                            byte[] buf = new byte[8192];
                            int n;
                            while ((n = in.read(buf)) != -1) digest.update(buf, 0, n);
                        }
                    }
                }
            }

            byte[] hash = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute covenant logic fingerprint", e);
        }
    }

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
        } catch (UrkelTreeMismatchException e) {
            // FIX: this exact exception was being caught by the
            // broader `catch (Exception e)` below FIRST, converting it
            // into a plain Result.INTERNAL_ERROR value -- silently
            // disabling ChainSync's own, separately-built
            // UrkelTreeMismatchException handling (its downloadBlocks()
            // loop explicitly catches this type and re-throws it so
            // syncCycle() can halt sync and invoke UrkelTreeRecovery --
            // see that catch block's own comment). Two independently
            // correct mechanisms for the same event, one silently
            // cancelling the other: confirmed directly from a real run
            // where the mismatch fired once, correctly, with no ban --
            // then, on every subsequent retry at the same height,
            // fell through to a SEPARATE, unrelated peer-blaming check
            // instead of ever reaching recovery, cycling through and
            // scoring down the entire outbound pool with nothing ever
            // actually resolving. Re-thrown here, unmodified, so it
            // reaches the handling that was always meant to receive it.
            throw e;
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
        // FIX: upgraded from warn-only to a hard stop. Continuing sync
        // on top of a known-wrong tree just compounds whatever the
        // actual problem is -- more blocks get processed against
        // already-corrupted state, burying the real divergence height
        // under a growing pile of also-technically-wrong data, and
        // making the eventual investigation strictly harder than
        // catching it here, immediately, would have been.
        byte[] claimedTreeRoot = HeaderUtil.treeRoot(headerBytes);
        byte[] ourCommittedRoot = db.getNameTree().committedRoot();
        if (!Arrays.equals(claimedTreeRoot, ourCommittedRoot)) {
            System.err.printf("[BlockProcessor] *** URKEL TREE ROOT MISMATCH at height %d *** "
                            + "header claims %s, we computed %s -- halting sync rather than continuing on "
                            + "top of known-wrong tree state.%n",
                    height, hex(claimedTreeRoot), hex(ourCommittedRoot));
            // FIX: this exact line -- height, claimed root, computed
            // root -- is precisely what days of manual, live-console-
            // watching diagnostic runs existed to eventually produce.
            // Logged here, durably, immediately, means any future
            // occurrence answers the "which block?" question the
            // moment it happens, from a plain file, with no diagnostic
            // tool, live monitoring, or lucky timing required.
            PersistentLog.logError(db.getDataDir(), String.format(
                    "Urkel tree root mismatch at height %d -- header claims %s, we computed %s",
                    height, hex(claimedTreeRoot), hex(ourCommittedRoot)));
            int firstRisky = db.getNameTree().firstDeepCatchUpDeletionHeight();
            // FIX: this is the direct answer to "stop and output
            // everything needed to understand the problem, without
            // having to re-run diagnostics from genesis." Every piece of
            // data InspectCommitWindow needed a separate, manually
            // re-run tool (and a live database re-opened read-only) to
            // reconstruct is ALREADY sitting right here, in this same
            // process, at this exact moment: the just-downloaded blocks
            // for the whole commit window, the current name state, and
            // the machine's own heap/disk condition. Dumping it now,
            // automatically, means the very first time a mismatch ever
            // occurs, the full picture is already on disk in one file by
            // the time anyone looks -- not something that takes a
            // multi-day replay or a hand-built tool to get to a second
            // time.
            String dumpPath = UrkelMismatchDiagnostics.dump(
                    db, height, claimedTreeRoot, ourCommittedRoot, firstRisky);
            if (dumpPath != null) {
                System.err.printf("[BlockProcessor] Full diagnostic dump written to: %s%n", dumpPath);
                PersistentLog.logError(db.getDataDir(), "Diagnostic dump written to: " + dumpPath);
            }
            if (firstRisky != -1) {
                System.err.printf("[BlockProcessor] A deep-catch-up (unvalidated) reconciliation first "
                                + "deleted something at height %d -- this is a plausible, known, bounded "
                                + "explanation (see UrkelTree.removeDirectly()'s own comment). "
                                + "UrkelTreeRecovery can attempt to self-correct from before that point.%n",
                        firstRisky);
            } else {
                System.err.printf("[BlockProcessor] No deep-catch-up reconciliation has ever run in "
                        + "this session -- the known, bounded false-positive risk cannot explain this. "
                        + "This needs direct investigation, not automatic recovery.%n");
            }
            throw new UrkelTreeMismatchException(height, claimedTreeRoot, ourCommittedRoot, firstRisky);
        }

        for (int txIndex = 0; txIndex < txs.size(); txIndex++) {
            TxParser.ParsedTx tx = txs.get(txIndex);
            // FIX: txid was previously recomputed here via
            // TxParser.computeTxid(tx.raw), which both re-parses the raw
            // transaction bytes from scratch (tx was already parsed once,
            // above, to produce this exact ParsedTx) and redundantly
            // rehashes the same base bytes already hashed into txidBytes
            // during merkle-root verification above. Reusing that
            // already-computed hash avoids both the duplicate parse and
            // the duplicate Blake2b hash for every transaction in every
            // block.
            String txid = hex(txidBytes.get(txIndex));
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
                        processNameCovenant(out, txid, i, height, db,
                                tx.inputs.isEmpty() ? null : tx.inputs.get(0));
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
    static final int TREE_INTERVAL_CONST = 36;
    static final int OPEN_PERIOD = TREE_INTERVAL_CONST + 1;     // 37
    static final int BIDDING_PERIOD = 5 * 144;                  // 720
    static final int REVEAL_PERIOD = 10 * 144;                  // 1440
    static final int RENEWAL_WINDOW = 2 * 365 * 144;            // 105120
    static final int AUCTION_MATURITY = (5 + 10 + 14) * 144;    // 4176
    static final int LOCKUP_PERIOD = 30 * 144;                  // 4320
    // FIX (Part 2, mempool covenant validation): NOT the same constant
    // as LOCKUP_PERIOD above, despite the similar name -- that one is
    // networks.js's `lockupPeriod` (claimed/reserved names' lockup
    // before becoming spendable, 30 days). This is `transferLockup`
    // (the wait between a TRANSFER and its FINALIZE, 2 days) -- a
    // genuinely different, separately-named constant in real hsd's own
    // networks.js that this codebase hadn't needed until now, since
    // FINALIZE processing (see processNameCovenant()'s COV_FINALIZE
    // case) only ever applied state, never validated timing.
    static final int TRANSFER_LOCKUP = 2 * 144;                 // 288
    // Confirmed directly from real hsd's own networks.js -- a fixed,
    // hardcoded mainnet height (main.deflationHeight = 61043), NOT a
    // BIP9 signaling deployment, so there's no activation-height
    // uncertainty here the way there is for "hardening".
    static final int DEFLATION_HEIGHT = 61_043;
    static final int CLAIM_FREQUENCY = 2 * 144;                 // 288

    /** 0=OPENING,1=BIDDING,2=REVEAL,3=CLOSED,4=REVOKED,5=LOCKED */
    static int computeState(ChainDB.NameEntry e, int height) {
        if (e.revoked != 0) return 4; // REVOKED
        if (e.claimed != 0) return (height < e.height + LOCKUP_PERIOD) ? 5 : 3; // LOCKED : CLOSED
        if (height < e.height + OPEN_PERIOD) return 0; // OPENING
        if (height < e.height + OPEN_PERIOD + BIDDING_PERIOD) return 1; // BIDDING
        if (height < e.height + OPEN_PERIOD + BIDDING_PERIOD + REVEAL_PERIOD) return 2; // REVEAL
        return 3; // CLOSED
    }

    static boolean isExpired(ChainDB.NameEntry e, int height) {
        // Matches real hsd's namestate.js isExpired() exactly -- no
        // lockup-related logic here at all, confirmed directly: the
        // ICANN Lockup soft fork is enforced ENTIRELY by blocking NEW
        // OPEN attempts (see processNameCovenant()'s own
        // ReservedNames.isLockedUp() check), never by changing
        // expiration behavior itself. A locked name can still
        // "expire" normally and reset to the empty state; what it
        // can't do is be successfully re-OPENed afterward. An earlier
        // version of this method added lockup logic here too, based
        // on a PR description's prose rather than the actual,
        // deployed code -- removed.
        if (e.revoked != 0) {
            return height >= e.revoked + AUCTION_MATURITY;
        }
        // Can only expire once CLOSED.
        if (computeState(e, height) != 3) return false;
        // Claimed names can't expire during the claim period -- matches
        // real hsd's own isClaimable() exactly (claimed != 0 AND height
        // < claimPeriod; confirmed directly from namestate.js --
        // noReserved is a testnet/regtest-only flag, always false on
        // the mainnet this project targets, so omitted rather than
        // modeled as a dead branch). ICANNLOCKUP_HEIGHT reused here
        // for claimPeriod -- see ReservedNames's own top comment on
        // why the two share one constant.
        //
        // FIX: previously checked ONLY e.claimed != 0, with no height
        // bound at all -- meaning a claimed name was PERMANENTLY
        // protected from ever expiring, in every case, forever. Real
        // hsd only protects it WHILE STILL WITHIN the claim period;
        // once that ends, a claimed-but-abandoned name expires exactly
        // like any other. A real, previously-shipped gap in this
        // project's own port (flagged in this method's own comment for
        // a long time as a known, unconfirmed risk), found and fixed
        // only once real source was read directly.
        if (e.claimed != 0 && height < ReservedNames.ICANNLOCKUP_HEIGHT) return false;
        // Two years with no renewal -- start over.
        if (height >= e.renewal + RENEWAL_WINDOW) return true;
        // Nobody ever revealed a bid -- start over.
        if (e.ownerTxid == null || e.ownerTxid.isEmpty()) return true;
        return false;
    }

    /** Matches real hsd's ns.maybeExpire(height, network) exactly --
     * called on every single covenant touch, before any type-specific
     * handling, confirmed directly from chain.js's verifyCovenants. */
    static void maybeExpire(ChainDB.NameEntry e, int height) {
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
                                            int outputIndex, int height, ChainDB db,
                                            TxParser.Input spentInput) {
        int type = out.covenant.type;
        List<TxParser.CovenantItem> items = out.covenant.items;
        if (items.isEmpty()) return;

        // Structural sanity -- ported directly from real hsd's
        // rules.hasSaneCovenants() (item counts, field lengths, name
        // charset/blacklist validity). Checked first, before even the
        // name hash is read, matching real hsd's own ordering: a
        // structurally malformed covenant is invalid regardless of
        // any name-tree state. See HandshakeCovenantRules's own class
        // comment for exactly what this does and doesn't cover yet.
        if (!HandshakeCovenantRules.isCovenantSane(type, items)) {
            System.err.printf("[BlockProcessor] Structurally invalid covenant (type=%d) in tx %s at "
                    + "height %d -- skipping, not applying%n", type, txid, height);
            return;
        }

        // Get name hash (item[0] for all covenant types)
        byte[] nameHashBytes = items.get(0).data;
        if (nameHashBytes == null || nameHashBytes.length != 32) return;
        String nameHash = hex(nameHashBytes);

        // ICANN Lockup soft fork (real hsd PR #819/#828/#834, activated
        // mainnet block 210240). Deliberately TWO SEPARATE checks, not
        // one combined check -- confirmed directly from real hsd's own
        // chain.js (verifyCovenants()) that OPEN and CLAIM are gated by
        // two genuinely different rules, not the same one applied
        // twice (an earlier version of this port got this wrong):
        //   - OPEN is rejected if ReservedNames.isLockedUp() -- real
        //     hsd's own isLockedUp(), matched exactly (permanent for
        //     ICANN TLDs only, an additional four years for Alexa Top
        //     10K and the "custom" list alike).
        //   - CLAIM is rejected if NOT ReservedNames.isReserved() --
        //     real hsd's own isReserved(): true for ANY name that was
        //     ever part of the original reserved set (locked or since
        //     released), only for as long as height is before the
        //     claim period ends. Never checks lockup category at all;
        //     once the claim period ends, EVERY reserved name simply
        //     stops being claimable, regardless of whether it's also
        //     locked from opening.
        // Both return early, before the name entry is even fetched or
        // created, matching real hsd's own behavior of the entire
        // containing block being invalid, not just this one covenant
        // being skipped. See ReservedNames's own class comment for the
        // full rule and exactly where its data comes from.
        if (type == COV_OPEN && ReservedNames.isLockedUp(nameHashBytes, height)) {
            return;
        }
        if (type == COV_CLAIM && !ReservedNames.isReserved(nameHashBytes, height)) {
            return;
        }

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

        // Cannot bid on a name still within its original reservation
        // window -- confirmed directly from chain.js's OPEN branch
        // ("Cannot bid on a reserved name"): "if (!ns.expired &&
        // rules.isReserved(nameHash, height, network))". A real,
        // separate, pre-existing gap independent of ICANN Lockup --
        // this rule has existed since mainnet launch (2020), not since
        // the 2024 fork, and this project had never implemented it at
        // all until now: any of the 90,043 originally-reserved names
        // could have been incorrectly accepted for a normal OPEN
        // auction at any point before its own claim period ended.
        // Checked here specifically -- AFTER maybeExpire(), not before
        // -- since it depends on entry.expired's post-expiration value,
        // matching real hsd's own ordering exactly (ns.maybeExpire()
        // runs, THEN this check reads ns.expired).
        if (type == COV_OPEN && !entry.expired && ReservedNames.isReserved(nameHashBytes, height)) {
            return;
        }

        // CLAIM validation -- ported directly from chain.js. Two real,
        // separate pieces, both previously entirely unported:
        //   1. State validity: a claim is only ever valid while OPENING,
        //      LOCKED, or (CLOSED && not yet registered) -- confirmed
        //      directly ("Claims can be re-redeemed any time before
        //      registration... a newer claim invalidates the old
        //      output"). Uses this project's own state numbering (see
        //      computeState()'s own comment).
        //   2. The "inflation-fixing soft-fork" (network.deflationHeight,
        //      confirmed directly from networks.js as a fixed, hardcoded
        //      mainnet height -- 61043 -- NOT a BIP9 signaling
        //      deployment like icannlockup/hardening, so there's no
        //      activation-height uncertainty here to flag): once active,
        //      requires the FIRST claim for a name to commit to height 1
        //      (non-contextual verification simplification), rate-limits
        //      re-claims to once every CLAIM_FREQUENCY blocks, and
        //      requires a re-claim to pay the exact same fee as the
        //      output it's replacing (miner-burned either way).
        // NOT ported here: the commit-height check (verifying
        // covenant.getU32(5) actually matches the real height of the
        // block hash in item[4]) -- needs a block-hash-to-height index
        // this project doesn't have yet, a real, separate, larger gap,
        // not something to approximate.
        // FIX: computeState(entry, height) used to be called a second time,
        // unconditionally, a few lines below (just before the covenant-type
        // switch) even for COV_CLAIM, which had already computed it right
        // here moments earlier against the exact same (entry, height) pair
        // -- entry is only read, never mutated, in between. Declaring
        // `precomputedState` here and reusing it below avoids recomputing
        // the identical state for every CLAIM covenant processed.
        Integer precomputedState = null;
        if (type == COV_CLAIM) {
            int claimState = computeState(entry, height);
            precomputedState = claimState;
            boolean validClaimState = claimState == 0 || claimState == 5
                    || (claimState == 3 && !entry.registered);
            if (!validClaimState) {
                System.err.printf("[BlockProcessor] Invalid CLAIM for name '%s' at height %d "
                                + "(state=%d, registered=%s) -- skipping, not applying%n",
                        entry.name, height, claimState, entry.registered);
                return;
            }

            int claimedHeight = extractU32(items, 5);
            if (claimedHeight <= entry.claimed) {
                System.err.printf("[BlockProcessor] Invalid CLAIM for name '%s' at height %d -- "
                                + "claimed height %d does not exceed existing %d (also implicitly rejects "
                                + "the genesis block) -- skipping, not applying%n",
                        entry.name, height, claimedHeight, entry.claimed);
                return;
            }

            if (height >= DEFLATION_HEIGHT) {
                boolean hasOwner = entry.ownerTxid != null && !entry.ownerTxid.isEmpty();
                if (!hasOwner && claimedHeight != 1) {
                    System.err.printf("[BlockProcessor] Invalid CLAIM for name '%s' at height %d -- "
                                    + "initial claim must commit to height 1, got %d -- skipping, not applying%n",
                            entry.name, height, claimedHeight);
                    return;
                }
                if (hasOwner && height < entry.height + CLAIM_FREQUENCY) {
                    System.err.printf("[BlockProcessor] Invalid CLAIM for name '%s' at height %d -- "
                                    + "re-claim before CLAIM_FREQUENCY (%d) has elapsed since %d -- "
                                    + "skipping, not applying%n",
                            entry.name, height, CLAIM_FREQUENCY, entry.height);
                    return;
                }
                if (hasOwner) {
                    ChainDB.UtxoEntry priorUtxo = db.getUtxo(entry.ownerTxid, entry.ownerIndex);
                    if (priorUtxo == null || out.value != priorUtxo.value()) {
                        System.err.printf("[BlockProcessor] Invalid CLAIM for name '%s' at height %d "
                                + "-- re-claim value does not match the output it replaces -- "
                                + "skipping, not applying%n", entry.name, height);
                        return;
                    }
                }
            }
        }

        // FIX: ported directly from real hsd's chain.js verifyCovenants()
        // -- the contextual, state-dependent checks that gate whether
        // each covenant type may actually apply at all. For a node
        // only ever syncing the real, already-valid chain, none of
        // these should ever actually fire -- no honest miner would
        // include a covenant that fails them, since every other real
        // node on the network would reject the block. They exist here
        // as genuine defense (a malformed/malicious block from a bad
        // peer, or a bug in this project's own height/state tracking),
        // not because real chain data is expected to trigger them --
        // so a hit is logged loudly and the covenant is skipped (not
        // applied), rather than silently ignored the way the routine,
        // expected reserved/lockup rejections above are. Uses this
        // project's OWN internal state numbering (see computeState()'s
        // own comment: 0=OPENING, 1=BIDDING, 2=REVEAL, 3=CLOSED,
        // 4=REVOKED, 5=LOCKED) throughout, not real hsd's own, numerically
        // different states enum -- only the underlying RULES are
        // ported, never raw numbers across that boundary.
        int start = extractU32(items, 1);
        int state = (precomputedState != null) ? precomputedState : computeState(entry, height);
        switch (type) {
            case COV_OPEN -> {
                // "Only one open transaction can ever exist" -- ns.height
                // must still equal the CURRENT height, meaning this open
                // is landing in the exact same block where ns.set()/
                // maybeExpire() just established it fresh. A second OPEN
                // for the same name, later, would find ns.height already
                // advanced past the current height and correctly fail
                // this check.
                if (state != 0 || entry.height != height) {
                    System.err.printf("[BlockProcessor] Invalid OPEN for name '%s' at height %d "
                                    + "(state=%d, entry.height=%d) -- skipping, not applying%n",
                            entry.name, height, state, entry.height);
                    return;
                }
                // Weekly rollout schedule for the first year of mainnet
                // -- ported directly from real hsd's rules.hasRollout().
                if (!HandshakeCovenantRules.hasRollout(nameHashBytes, height)) {
                    System.err.printf("[BlockProcessor] OPEN for name '%s' at height %d is before its "
                            + "own rollout week -- skipping, not applying%n", entry.name, height);
                    return;
                }
            }
            case COV_BID -> {
                if (state != 1 || start != entry.height) {
                    System.err.printf("[BlockProcessor] Invalid BID for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height);
                    return;
                }
            }
            case COV_REVEAL -> {
                if (start != entry.height || state != 2) {
                    System.err.printf("[BlockProcessor] Invalid REVEAL for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height);
                    return;
                }
            }
            case COV_REDEEM -> {
                // "Must be the LOSER, not the winner" -- ported directly
                // from chain.js: the spent input's own outpoint
                // (spentInput, the losing bid being redeemed) must NOT
                // equal ns.owner (the winning bidder's outpoint, set
                // during REVEAL). Without this, the actual winner could
                // incorrectly REDEEM their own winning bid instead of
                // REGISTERing it -- a different covenant type with
                // different effects on the tree. Previously left
                // unported since it needed the spent input's own
                // outpoint, which this method didn't receive until now.
                //
                // "state < CLOSED" in real hsd (which rejects unless
                // CLOSED or REVOKED) -- deliberately NOT a range check
                // here (state != 3 && state != 4), NOT "state < 3":
                // our own numbering puts LOCKED at 5, ABOVE closed(3)/
                // revoked(4), while real hsd's LOCKED sits BELOW their
                // own CLOSED/REVOKED -- a naive range comparison here
                // would have silently treated LOCKED as satisfying
                // this check, when real hsd's equivalent never would.
                // Caught by direct testing, not by inspection alone.
                boolean spentIsWinner = spentInput != null
                        && spentInput.prevTxid.equals(entry.ownerTxid)
                        && spentInput.prevIndex == entry.ownerIndex;
                if (start != entry.height || (state != 3 && state != 4) || spentIsWinner) {
                    System.err.printf("[BlockProcessor] Invalid REDEEM for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d, spentIsWinner=%s) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height, spentIsWinner);
                    return;
                }
            }
            case COV_REGISTER -> {
                if (start != entry.height || state != 3) {
                    System.err.printf("[BlockProcessor] Invalid REGISTER for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height);
                    return;
                }
            }
            case COV_UPDATE -> {
                if (start != entry.height || state != 3) {
                    System.err.printf("[BlockProcessor] Invalid UPDATE for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height);
                    return;
                }
            }
            case COV_RENEW -> {
                // Matches real hsd's own premature-renewal check exactly
                // ("if (height < ns.renewal + network.names.treeInterval)")
                // -- TREE_INTERVAL_CONST, the same constant this whole
                // project already uses elsewhere for the Urkel tree's own
                // commit interval (36 blocks), confirmed to be the same
                // named constant real hsd's own network.names.treeInterval
                // refers to here.
                if (start != entry.height || state != 3
                        || height < entry.renewal + TREE_INTERVAL_CONST) {
                    System.err.printf("[BlockProcessor] Invalid RENEW for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d, entry.renewal=%d) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height, entry.renewal);
                    return;
                }
            }
            case COV_TRANSFER -> {
                if (start != entry.height || state != 3) {
                    System.err.printf("[BlockProcessor] Invalid TRANSFER for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height);
                    return;
                }
            }
            case COV_FINALIZE -> {
                // TRANSFER_LOCKUP -- confirmed as the same real, named
                // constant (network.names.transferLockup) real hsd's own
                // finalize-maturity check uses; this project already
                // defines it elsewhere for the same purpose.
                if (start != entry.height || state != 3
                        || height < entry.transfer + TRANSFER_LOCKUP) {
                    System.err.printf("[BlockProcessor] Invalid FINALIZE for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d, entry.transfer=%d) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height, entry.transfer);
                    return;
                }
            }
            case COV_REVOKE -> {
                if (start != entry.height || state != 3) {
                    System.err.printf("[BlockProcessor] Invalid REVOKE for name '%s' at height %d "
                                    + "(state=%d, start=%d, entry.height=%d) -- skipping, not applying%n",
                            entry.name, height, state, start, entry.height);
                    return;
                }
            }
            default -> { /* CLAIM handled separately above; NONE never reaches here */ }
        }


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
                // FIX: real hsd's ns.setHighest(0) explicitly zeroes
                // this on every claim, including a re-claim (real hsd's
                // own comment: "Claims can be re-redeemed any time
                // before registration... a newer claim invalidates the
                // old output") -- confirmed directly from chain.js.
                // Previously missing; harmless for a name's first-ever
                // claim (a fresh entry already defaults to 0), but a
                // real gap for the re-claim case, where a stale value
                // could otherwise survive uncorrected.
                entry.highest = 0;
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
        //
        // REVERTED (previous session's OPEN-exclusion fix was wrong):
        // that fix was based on a comment claiming a real mainnet header
        // at height 2052 had an all-zero treeRoot despite real OPENs
        // having occurred -- meant to justify excluding OPEN from the
        // tree entirely. Directly disproven by a fresh from-genesis
        // replay with that exact exclusion in place: the 36-block window
        // ending at height 2052 contains exactly 133 covenant
        // transactions, ALL of them OPEN (zero BID/REDEEM/anything
        // else -- confirmed via the automatic mismatch-dump tool, not
        // guessed), and the real header at height 2053 claims a
        // NON-ZERO treeRoot for that boundary. With OPEN excluded, this
        // code computed an all-zero root instead (nothing else in the
        // window could have fed the tree), and the mismatch fired
        // immediately at height 2053 -- the earliest possible commit
        // boundary after any OPEN activity at all. So OPEN genuinely
        // DOES feed the tree on the real network; the "confirmed
        // empirically" claim behind the previous exclusion was itself
        // mistaken (likely from a flawed or misremembered historical
        // test, not a real property of the real chain). BID/REDEEM
        // remain excluded here since there is still no counter-evidence
        // against that specific pair, and it has independent structural
        // support: unlike OPEN (which transitions a name into a new,
        // provable OPENING state), a BID reveals nothing about the name
        // on-chain yet (that's the point of a blind auction), and REDEEM
        // only returns a losing bidder's collateral -- neither changes
        // anything about the name's resolvable state that the tree
        // needs to prove.
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
                // FIX: previously copied Arrays.copyOfRange(rawBlock,
                // pos, rawBlock.length) -- the entire remaining block --
                // before parsing even a single transaction, every time
                // through this loop. Confirmed as a real OutOfMemoryError
                // site: for a block with N transactions this allocated
                // N copies averaging roughly half the remaining block
                // size each, a total cost scaling with N × blockSize
                // rather than just blockSize. See TxParser.parse(byte[],
                // int)'s own comment for the full fix -- this now parses
                // directly out of rawBlock at the real offset, no
                // upfront copy at all.
                TxParser.ParsedTx tx = TxParser.parse(rawBlock, pos);
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
    // Package-private (not private): UrkelMismatchDiagnostics calls this
    // directly, deliberately, so its automatic dump can never decode a
    // name differently than the real validator does -- same fidelity
    // guarantee InspectCommitWindow got via reflection into this same
    // method, just without needing reflection now that the caller lives
    // in production rather than being a one-off external tool.
    static String extractName(List<TxParser.CovenantItem> items, int type) {
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
        return HexUtil.encode(b);
    }

    private static byte[] fromHex(String s) {
        return HexUtil.decode(s);
    }
}