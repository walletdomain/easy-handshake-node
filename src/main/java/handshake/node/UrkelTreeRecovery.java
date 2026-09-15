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

    public static RecoveryResult attemptRecovery(ChainDB realDb, String dataDir,
                                                 UrkelTreeMismatchException cause,
                                                 boolean uncleanShutdownDetected) {
        int safeHeight;
        if (cause.firstDeepCatchUpDeletionHeight != -1) {
            // Known, specific risky height -- roll back to just before
            // it, same strategy as the original design.
            safeHeight = Math.max(0, cause.firstDeepCatchUpDeletionHeight - UrkelNameTree.TREE_INTERVAL);
            System.out.println("[UrkelTreeRecovery] Attempting automatic recovery. First deep-catch-up "
                    + "deletion was at height " + cause.firstDeepCatchUpDeletionHeight + " -- rolling back "
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
        deleteDir(scratchDir);

        ChainDB scratchDb = ChainDB.openScratch(scratchPath);
        boolean phase2 = false;

        try {
            Method processNameCovenant = BlockProcessor.class.getDeclaredMethod(
                    "processNameCovenant", TxParser.Output.class, String.class, int.class, int.class,
                    ChainDB.class);
            processNameCovenant.setAccessible(true);

            Field commitIntervalField = ChainSync.class.getDeclaredField("BLOCK_COMMIT_INTERVAL");
            commitIntervalField.setAccessible(true);
            int commitInterval = commitIntervalField.getInt(null);

            for (int height = 0; height <= realTipHeight; height++) {
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
                    for (int i = 0; i < tx.outputs.size(); i++) {
                        TxParser.Output out = tx.outputs.get(i);
                        if (out.covenant != null && out.covenant.type != 0) {
                            processNameCovenant.invoke(null, out, txid, i, height, scratchDb);
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
                    scratchDb.commit();
                    scratchDb.compact(1000);
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
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
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