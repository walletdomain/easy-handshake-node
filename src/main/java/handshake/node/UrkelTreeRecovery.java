package handshake.node;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

/** Self-healing recovery for an Urkel tree root mismatch -- see
 *  UrkelTreeMismatchException's own comment, and the extensive
 *  investigation this design followed from (the confirmed, ~0.1%,
 *  still-unexplained false-positive rate in the deep-catch-up
 *  reconciliation path -- see UrkelTree.removeDirectly()'s own
 *  comment), for the full reasoning.
 *
 *  Two-phase replay, entirely into a separate scratch ChainDB (via
 *  openScratch(), never touching the real, live db's own static
 *  instance -- see that method's own comment for why that distinction
 *  matters specifically because this runs inside the SAME process as
 *  the live node, unlike this project's earlier standalone diagnostic
 *  tools):
 *
 *  - Phase 1 (fast): replay height 0 -> safeHeight using NORMAL
 *    reconciliation pacing (deep-catch-up allowed wherever the real
 *    pacing logic would choose it). Safe specifically because
 *    safeHeight is the last real commit boundary strictly BEFORE the
 *    first deep-catch-up deletion ever recorded in this run -- by
 *    definition, nothing was ever wrongly deleted in this range.
 *
 *  - Phase 2 (forced-safe): replay safeHeight+1 -> the real chain's
 *    current tip, with deep-catch-up reconciliation permanently
 *    disabled for the rest of the replay (bestKnownPeerHeight forced
 *    to 0, which -- per UrkelNameTree.maybeCommit()'s own documented
 *    meaning -- always selects the fully-validated walk path, never
 *    removeDirectly()). Every height's computed root is checked
 *    against its real header's claim along the way, the same check
 *    BlockProcessor itself does.
 *
 *  If phase 2 ever hits ANOTHER mismatch, that's decisive: the known,
 *  bounded deep-catch-up risk did NOT explain the original mismatch,
 *  since phase 2 never used that path at all. Recovery reports failure
 *  and nothing is swapped into the real database -- an unexplained
 *  mismatch needs a person, not an automatic "fix" for a cause that
 *  was just proven wrong.
 *
 *  If phase 2 reaches the real tip clean, the scratch replay's node
 *  data and final root values get folded into the real database via a
 *  safe, chunked, meta-gated swap -- see swapIn()'s own comment for why
 *  an interruption at any point during that copy can never corrupt the
 *  live database. */
public class UrkelTreeRecovery {

    public static class RecoveryResult {
        public final boolean success;
        public final String message;
        RecoveryResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    private static final int SWAP_CHUNK_SIZE = 20_000;

    // Resumability -- confirmed as a real, substantial cost without
    // this: one real run lost 16 hours of progress (reaching block
    // 160,000 of ~348,000) to exactly this, since the replay
    // previously always deleted any existing scratch data and started
    // over from genesis, every single invocation. These two keys,
    // stored in the SCRATCH database's own meta map (never the real
    // one), are what make resuming safe rather than just fast:
    // SCRATCH_PROGRESS_HEIGHT_KEY records the last height whose tree
    // data is durably committed, and SCRATCH_SAFE_HEIGHT_KEY records
    // which safeHeight that progress was made under -- if a later
    // invocation passes a DIFFERENT safeHeight (a changed
    // knownDeletionHeight, or updated covenant-processing logic that
    // would behave differently), the mismatch is caught and this
    // falls back to starting fresh rather than resuming under a stale,
    // no-longer-valid assumption.
    private static final String SCRATCH_PROGRESS_HEIGHT_KEY = "scratch_replay_progress_height";
    private static final String SCRATCH_SAFE_HEIGHT_KEY = "scratch_replay_safe_height";
    // See BlockProcessor.computeCovenantLogicFingerprint()'s own
    // comment for the full reasoning -- a real, previously-missing
    // safeguard here specifically: this is production code the real
    // node relies on for automatic recovery, so a resumed replay
    // silently mixing progress computed under old covenant-processing
    // logic with new logic applied from that point forward would have
    // produced a result with no reliable meaning at all.
    private static final String SCRATCH_LOGIC_FINGERPRINT_KEY = "scratch_replay_logic_fingerprint";

    public static RecoveryResult attemptRecovery(ChainDB realDb, String dataDir,
                                                 int firstDeepCatchUpDeletionHeight,
                                                 boolean uncleanShutdownDetected) {
        int safeHeight;
        if (firstDeepCatchUpDeletionHeight != -1) {
            // Known, specific risky height -- roll back to just before
            // it, same strategy as the original design.
            safeHeight = Math.max(0, firstDeepCatchUpDeletionHeight - UrkelNameTree.TREE_INTERVAL);
            System.out.println("[UrkelTreeRecovery] Attempting automatic recovery. First deep-catch-up "
                    + "deletion was at height " + firstDeepCatchUpDeletionHeight + " -- rolling back "
                    + "to height " + safeHeight + " and replaying forward with the fully-validated walk "
                    + "forced on for the rest of the replay.");
        } else if (uncleanShutdownDetected) {
            // NEW: resilience support -- no specific known-risky height
            // to target here, unlike the deep-catch-up case above. The
            // previous run simply didn't exit cleanly (see Main's own
            // shutdown-hook comment for why that's a reliable signal,
            // not a guess), so there's no fine-grained tracking of
            // exactly where -- if anywhere -- an inconsistency was
            // introduced. Genesis is the only point that's guaranteed
            // to never have been subject to an in-flight, uncommitted
            // write at the moment of the interruption. Expensive, but
            // this is meant to be a rare, belt-and-suspenders path, not
            // the common case -- the commit/reconciliation-ordering fix
            // this was built alongside (see ChainDB.commit()'s own
            // comment) directly targets making the underlying race rare
            // in the first place, not just recoverable after the fact.
            safeHeight = 0;
            System.out.println("[UrkelTreeRecovery] Attempting automatic recovery after detecting an "
                    + "unclean shutdown with no specific known-risky height to target -- rolling back to "
                    + "genesis and replaying the entire chain with the fully-validated walk forced on "
                    + "throughout.");
        } else {
            // No basis for automatic recovery -- see this field's own
            // comment on UrkelNameTree. Attempting a "fix" here would
            // have no justified basis and could mask a real, different
            // bug rather than actually correct anything.
            return new RecoveryResult(false, "No deep-catch-up reconciliation has ever run in this "
                    + "session, and no unclean shutdown was detected -- neither known, bounded explanation "
                    + "applies. Automatic recovery was not attempted; this needs direct investigation.");
        }

        int realTipHeight = realDb.getBlockTip();

        String scratchDir = dataDir + "-recovery-scratch";
        String scratchPath = scratchDir + File.separator + "chain.mv.db";
        // Fingerprints EVERY compiled class in the handshake.node
        // package -- see computeCovenantLogicFingerprint()'s own
        // comment for why this needs to cover the whole package, not
        // a hand-picked list of "the classes that matter."
        String currentFingerprint = BlockProcessor.computeCovenantLogicFingerprint();

        // Look for a resumable prior attempt before deleting anything
        // -- see this class's own SCRATCH_PROGRESS_HEIGHT_KEY comment
        // for why this exists at all. Opens the existing scratch data
        // (if any) just to read its marker keys, then closes it
        // again -- the real replay below opens it fresh either way,
        // so this is a small, one-time, negligible cost against a
        // replay that runs for hours.
        int resumeFromHeight = 0;
        boolean resuming = false;
        if (new File(scratchDir).exists()) {
            ChainDB existingScratch = null;
            try {
                existingScratch = ChainDB.openScratch(scratchPath);
                KVMap<String, String> existingMeta = existingScratch.metaMapForRecovery();
                String storedSafeHeight = existingMeta.get(SCRATCH_SAFE_HEIGHT_KEY);
                String storedProgress = existingMeta.get(SCRATCH_PROGRESS_HEIGHT_KEY);
                String storedFingerprint = existingMeta.get(SCRATCH_LOGIC_FINGERPRINT_KEY);
                if (storedProgress != null && storedFingerprint == null) {
                    System.out.println("[UrkelTreeRecovery] Found prior progress, but it predates this "
                            + "tool's own logic-fingerprint safeguard, so which covenant-processing logic "
                            + "produced it can't be confirmed -- starting over from genesis rather than "
                            + "risk silently mixing rule sets.");
                } else if (storedProgress != null && !currentFingerprint.equals(storedFingerprint)) {
                    System.out.println("[UrkelTreeRecovery] Found prior progress, but it was computed under "
                            + "DIFFERENT covenant-processing logic (fingerprint " + storedFingerprint
                            + " vs. current " + currentFingerprint + ") -- starting over from genesis "
                            + "rather than silently mixing old and new rules across a resumed run.");
                } else if (storedSafeHeight != null && storedProgress != null
                        && Integer.parseInt(storedSafeHeight) == safeHeight) {
                    int progress = Integer.parseInt(storedProgress);
                    if (progress >= 0 && progress <= realTipHeight) {
                        resumeFromHeight = progress + 1;
                        resuming = true;
                        System.out.println("[UrkelTreeRecovery] Found a resumable scratch replay from a "
                                + "previous attempt, already durably progressed through height " + progress
                                + " under the SAME covenant-processing logic -- resuming from "
                                + resumeFromHeight + " instead of starting over from genesis.");
                    }
                }
            } catch (Exception e) {
                // Anything at all wrong with the existing scratch data
                // -- unreadable, corrupted, missing markers from an
                // older version of this tool -- falls safely back to
                // starting fresh below. Never trust partial data this
                // can't fully verify; a wasted few hours redoing work
                // is a far better outcome than silently resuming from
                // something subtly broken.
                System.out.println("[UrkelTreeRecovery] An existing scratch replay exists but could not be "
                        + "safely resumed (" + e.getMessage() + ") -- starting over from genesis instead.");
            } finally {
                if (existingScratch != null) existingScratch.close();
            }
        }

        if (!resuming) {
            deleteDir(scratchDir);
        }

        ChainDB scratchDb = ChainDB.openScratch(scratchPath);
        // Recomputed correctly on resume, not just left false until the
        // loop naturally reaches safeHeight again -- resuming partway
        // through phase 2 must keep the fully-validated walk forced on
        // from the very first height processed this run, exactly as it
        // would have been if this were one continuous, uninterrupted
        // replay.
        boolean phase2 = resumeFromHeight > safeHeight;

        try {
            Method processNameCovenant = BlockProcessor.class.getDeclaredMethod(
                    "processNameCovenant", TxParser.Output.class, String.class, int.class, int.class,
                    ChainDB.class, TxParser.Input.class);
            processNameCovenant.setAccessible(true);

            Method serializeCovenant = BlockProcessor.class.getDeclaredMethod(
                    "serializeCovenant", TxParser.Covenant.class);
            serializeCovenant.setAccessible(true);

            Field commitIntervalField = ChainSync.class.getDeclaredField("BLOCK_COMMIT_INTERVAL");
            commitIntervalField.setAccessible(true);
            int commitInterval = commitIntervalField.getInt(null);

            for (int height = resumeFromHeight; height <= realTipHeight; height++) {
                byte[] rawBlock = realDb.getBlock(height);
                if (rawBlock == null) break;

                if (height > safeHeight) {
                    phase2 = true;
                    byte[] headerBytes = Arrays.copyOf(rawBlock, Math.min(236, rawBlock.length));
                    byte[] claimed = HeaderUtil.treeRoot(headerBytes);
                    byte[] computed = scratchDb.getNameTree().committedRoot();
                    if (!Arrays.equals(claimed, computed)) {
                        System.out.println("[UrkelTreeRecovery] Mismatch reoccurred at height " + height
                                + " during the forced-safe replay -- the known deep-catch-up risk was NOT "
                                + "the actual cause. Aborting recovery; nothing will be swapped in.");
                        return new RecoveryResult(false, "Forced-safe replay hit a mismatch again at "
                                + "height " + height + " -- this rules out the known deep-catch-up risk as "
                                + "the explanation. A different, unexplained problem needs direct "
                                + "investigation.");
                    }
                }

                List<TxParser.ParsedTx> txs = BlockProcessor.parseBlockTxs(rawBlock);
                for (TxParser.ParsedTx tx : txs) {
                    String txid = TxParser.computeTxid(tx.raw);
                    if (txid == null) continue;
                    TxParser.Input spentInput = tx.inputs.isEmpty() ? null : tx.inputs.get(0);

                    // PERFORMANCE FIX: see UrkelDivergenceFinder's own
                    // identical comment for the full reasoning -- this
                    // previously saved a UTXO entry for EVERY output of
                    // EVERY transaction in the entire chain (and
                    // attempted a removal for every input), when
                    // db.getUtxo() is only ever called from CLAIM's own
                    // re-claim-value check, which can only ever resolve
                    // to a PRIOR CLAIM's own output. Confirmed as the
                    // dominant cost behind a real, measured slowdown.
                    // The removal loop is dropped entirely, not just
                    // narrowed: a UTXO's value never changes once
                    // written, so a stale-but-present entry for an
                    // already-spent claim output cannot produce a wrong
                    // answer, and a later re-claim looks up the NEW
                    // owner's own outpoint, never the old one.
                    for (int i = 0; i < tx.outputs.size(); i++) {
                        TxParser.Output out = tx.outputs.get(i);

                        if (out.covenant != null && out.covenant.type == TxParser.COV_CLAIM) {
                            byte[] covData = (byte[]) serializeCovenant.invoke(null, out.covenant);
                            ChainDB.UtxoEntry utxo = new ChainDB.UtxoEntry(
                                    out.value,
                                    out.addrVersion,
                                    out.addrHash,
                                    out.covenant.type,
                                    covData,
                                    spentInput == null || spentInput.isCoinbase(),
                                    height
                            );
                            scratchDb.saveUtxo(txid, i, utxo);
                        }

                        if (out.covenant != null && out.covenant.type != 0) {
                            processNameCovenant.invoke(null, out, txid, i, height, scratchDb, spentInput);
                        }
                    }
                }

                // Phase 1: real pacing (deep-catch-up allowed, safe by
                // construction in this range). Phase 2: bestKnownPeerHeight
                // forced to 0 -- per maybeCommit()'s own documented
                // meaning, this always selects the fully-validated walk.
                int bestKnownPeerHeight = phase2 ? 0 : realTipHeight;
                scratchDb.persistNameTreeStateTimed(height, bestKnownPeerHeight);

                if (height % commitInterval == 0 && height > 0) {
                    // Progress marker written BEFORE commit(), not
                    // after -- so the SAME commit() call that durably
                    // persists this height's tree data also durably
                    // persists the marker describing it, atomically.
                    // Writing it after would leave a real window where
                    // a kill could lose the marker even though the
                    // data it should have pointed to was already safe
                    // on disk, silently discarding otherwise-resumable
                    // progress right back to the exact problem this
                    // whole mechanism exists to fix.
                    KVMap<String, String> scratchMeta = scratchDb.metaMapForRecovery();
                    scratchMeta.put(SCRATCH_PROGRESS_HEIGHT_KEY, String.valueOf(height));
                    scratchMeta.put(SCRATCH_SAFE_HEIGHT_KEY, String.valueOf(safeHeight));
                    scratchMeta.put(SCRATCH_LOGIC_FINGERPRINT_KEY, currentFingerprint);
                    scratchDb.commit();
                    scratchDb.compact(1000);

                    // SAFETY NET: see UrkelDivergenceFinder's own
                    // identical comment for the full reasoning. Checked
                    // right after this commit, not before, so whatever
                    // exit this triggers always leaves a genuinely
                    // resumable checkpoint behind.
                    long usableBytes = new File(scratchDir).getUsableSpace();
                    long minSafeBytes = 10L * 1024 * 1024 * 1024;
                    if (usableBytes < minSafeBytes) {
                        // return, not System.exit() -- this method's
                        // real caller (attemptRecovery(), returning
                        // RecoveryResult) is the one Main's own startup
                        // path checks .success on before deciding
                        // whether to allow sync to proceed at all; a
                        // bare System.exit() here would skip that
                        // decision entirely when this runs as part of
                        // production startup recovery, not just as a
                        // standalone tool.
                        String message = String.format(
                                "Stopped due to low disk space: only %.1f GB free on the volume holding "
                                        + "the scratch database (below the %.0f GB safety margin) -- stopped "
                                        + "right after a durable commit at height %d, rather than risk an "
                                        + "uncontrolled write failure. This height's progress is safely "
                                        + "saved; free up disk space and rerun to resume from here.",
                                usableBytes / (1024.0 * 1024 * 1024), minSafeBytes / (1024.0 * 1024 * 1024),
                                height);
                        System.out.println();
                        System.out.println("[UrkelTreeRecovery] " + message);
                        return new RecoveryResult(false, message);
                    }
                }

                if (height % 5000 == 0) {
                    System.out.println("[UrkelTreeRecovery] Replayed through height " + height
                            + (phase2 ? " (forced-safe phase)" : " (fast phase)"));
                }
            }
        } catch (Exception e) {
            System.out.println("[UrkelTreeRecovery] Recovery replay failed with an exception: " + e);
            scratchDb.close();
            return new RecoveryResult(false, "Recovery replay failed with an exception: " + e);
        }

        // FIX: previously closed scratchDb here and reopened a fresh
        // instance for the swap phase -- a real correctness bug caught
        // before this ever ran: the tree's committedRoot() only ever
        // advances on TREE_INTERVAL boundaries by design (correctly
        // matching the real, live node's own committed root at this
        // point), but a close+reopen cycle depends on whatever was
        // DURABLY FLUSHED to disk, which the loop above only forces at
        // commitInterval-aligned heights -- not necessarily realTipHeight
        // itself. An explicit, unconditional commit() here, on the SAME
        // still-open instance (no reopen at all), is both simpler and
        // actually correct: the in-memory tree state is already right
        // regardless, and this just makes sure it's durably on disk
        // before the swap reads from it.
        scratchDb.commit();

        System.out.println("[UrkelTreeRecovery] Forced-safe replay reached the real tip (" + realTipHeight
                + ") with no further mismatch -- the known deep-catch-up risk is confirmed as the "
                + "explanation. Proceeding to fold the corrected state into the real database.");

        try {
            swapIn(realDb, scratchDb);
        } finally {
            scratchDb.close();
            deleteDir(scratchDir);
        }

        return new RecoveryResult(true, "Recovery succeeded -- the tree was independently re-derived "
                + "from height " + safeHeight + " forward using the fully-validated path the whole way, "
                + "confirmed to match every real header up to height " + realTipHeight + ", and folded "
                + "into the live database.");
    }

    /** Folds a verified-correct scratch tree into the real database.
     *  Safe against an interruption at any point: every chunk here only
     *  ADDS or OVERWRITES entries in the real urkelNodes map -- nothing
     *  is ever deleted from it, so the real database's EXISTING tree
     *  structure (whatever the current, still-official meta root values
     *  point at) remains fully intact and correctly resolvable
     *  throughout the whole copy. The meta keys that actually designate
     *  which root is official are updated only in the very last step,
     *  after every chunk has already succeeded -- a crash or kill at
     *  any point before that leaves the live database exactly as it
     *  was, with at most some extra, not-yet-referenced (and therefore
     *  completely harmless) node data left behind, which a later,
     *  ordinary reconciliation cycle will clean up regardless. */
    private static void swapIn(ChainDB realDb, ChainDB scratchDb) {
        KVMap<String, byte[]> realNodes = realDb.urkelNodesMapForRecovery();
        KVMap<String, byte[]> scratchNodes = scratchDb.urkelNodesMapForRecovery();

        Map<String, byte[]> chunk = new HashMap<>();
        int[] copied = {0};
        // Streaming key-by-key, then a separate get() per key, not
        // entrySet() -- confirmed directly that entrySet() eagerly
        // materializes its entire result into an in-memory List before
        // returning anything, the same unsafe-at-real-scale pattern
        // this project has already had to fix more than once elsewhere.
        // Slower (two round trips per entry instead of one), but this
        // is a rare recovery path, not a hot one -- memory safety here
        // matters more than shaving off the extra round trip.
        try (KVMap.KVSnapshot<String> snapshot = scratchNodes.openSnapshot()) {
            snapshot.forEachKey(key -> {
                byte[] value = scratchNodes.get(key);
                if (value != null) chunk.put(key, value);
                if (chunk.size() >= SWAP_CHUNK_SIZE) {
                    realNodes.putAll(new HashMap<>(chunk));
                    copied[0] += chunk.size();
                    chunk.clear();
                    System.out.println("[UrkelTreeRecovery] Swap: copied " + copied[0]
                            + " node entries so far");
                }
            });
        }
        if (!chunk.isEmpty()) {
            realNodes.putAll(chunk);
            copied[0] += chunk.size();
        }
        System.out.println("[UrkelTreeRecovery] Swap: copied " + copied[0] + " node entries total. "
                + "Activating the corrected root now.");

        // The activation step -- everything above this line is
        // reversible by simple irrelevance (extra data nothing points
        // at yet, if this were interrupted); this is the one write that
        // actually matters, done last and only after every chunk above
        // has already succeeded.
        KVMap<String, String> realMeta = realDb.metaMapForRecovery();
        realMeta.put(ChainDB.META_URKEL_COMMITTED_ROOT, hex(scratchDb.getNameTree().committedRoot()));
        realMeta.put(ChainDB.META_URKEL_LIVE_ROOT, hex(scratchDb.getNameTree().liveRoot()));

        System.out.println("[UrkelTreeRecovery] Swap complete. The real database's Urkel tree now "
                + "reflects the independently re-derived, verified-correct state.");
    }

    static String hex(byte[] b) {
        return HexUtil.encode(b);
    }

    static void deleteDir(String path) {
        File dir = new File(path);
        if (!dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) {
            if (f.isDirectory()) deleteDir(f.getPath()); else f.delete();
        }
        dir.delete();
    }
}