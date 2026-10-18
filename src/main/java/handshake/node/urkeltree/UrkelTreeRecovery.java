package handshake.node.urkeltree;

import handshake.node.util.HexUtil;

import handshake.node.storage.ChainDB;
import handshake.node.storage.KVMap;
import handshake.node.chain.BlockProcessor;
import handshake.node.chain.HeaderUtil;

import java.io.File;
import java.util.*;

/** Self-healing recovery for an Urkel tree root mismatch.
 *
 *  The tree is DERIVED data: a pure function of the names table. Recovery therefore
 *  rebuilds it from the names table (streamed into a scratch database) and accepts the
 *  result only if its root equals the root committed in the header after the tree
 *  boundary -- that equality is the proof. On success the rebuilt nodes are folded into the
 *  live database with a chunked, meta-gated swap (see swapIn()).
 *
 *  There is deliberately NO genesis-replay fallback any more. It took days, was never able to
 *  repair the names table, and could report success without having fixed anything. When the
 *  fast rebuild cannot apply or fails, recovery reports failure and the caller restores the
 *  latest verified snapshot (see SnapshotManager) -- the only other repair that is both
 *  fast and provably correct. */
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

    /** The parameters are kept for the callers' sake; the cause no longer changes the repair
     *  (it is the same fast rebuild whatever damaged the tree). */
    public static RecoveryResult attemptRecovery(ChainDB realDb, String dataDir,
                                                 int firstDeepCatchUpDeletionHeight,
                                                 boolean uncleanShutdownDetected) {
        return tryFastRebuild(realDb, dataDir, realDb.getBlockTip());
    }

    /** Rebuilds the Urkel tree from the names table alone. The tree is a
     *  pure function of the set of (nameHash -> state) leaves, so if the names
     *  table is right the rebuilt root must equal the root committed in the
     *  next block's header -- that equality is the proof. Returns a failed result
     *  whenever it cannot apply or the check fails; never swaps in anything
     *  unverified. */
    private static RecoveryResult tryFastRebuild(ChainDB realDb, String dataDir, int tip) {
        if (tip <= 0 || tip % UrkelNameTree.TREE_INTERVAL != 0) {
            System.out.println("[UrkelTreeRecovery] Fast rebuild not applicable (tip " + tip
                    + " is not on a " + UrkelNameTree.TREE_INTERVAL + "-block tree boundary).");
            return new RecoveryResult(false, "Fast rebuild is not applicable here: the node's tip is not on a "
                    + UrkelNameTree.TREE_INTERVAL + "-block tree boundary; restore the latest verified snapshot.");
        }
        if (realDb.hasPendingNameWrites()) {
            System.out.println("[UrkelTreeRecovery] Fast rebuild not applicable (unflushed name writes).");
            return new RecoveryResult(false, "Fast rebuild is not applicable (unflushed name writes); restore the latest verified snapshot.");
        }
        byte[] nextHeader = realDb.getHeader(tip + 1);
        if (nextHeader == null) {
            System.out.println("[UrkelTreeRecovery] Fast rebuild not applicable (no header for height "
                    + (tip + 1) + " to verify against).");
            return new RecoveryResult(false, "Fast rebuild is not applicable (the header after the boundary is not stored); restore the latest verified snapshot.");
        }
        byte[] expected = HeaderUtil.treeRoot(nextHeader);

        String scratchDir = dataDir + "-recovery-scratch";
        deleteDir(scratchDir);
        ChainDB scratchDb = null;
        try {
            System.out.println("[UrkelTreeRecovery] Fast rebuild: rebuilding the tree from the names table "
                    + "and checking it against the header at height " + (tip + 1) + " (expected root "
                    + hex(expected) + ").");
            long t0 = System.currentTimeMillis();
            scratchDb = ChainDB.openScratch(scratchDir + File.separator + "chain.mv.db");
            final ChainDB sdb = scratchDb;
            sdb.getNameTree().setPruningDisabled(true);
            long[] count = {0};
            realDb.forEachNameStreaming((nameHash, entry) -> {
                UrkelNameState st = BlockProcessor.toTreeState(entry);
                if (st.isNull()) return;
                sdb.getNameTree().applyNameState(nameHash, st);
                count[0]++;
                if (count[0] % 20_000 == 0) sdb.getNameTree().persistBlock();
                if (count[0] % 200_000 == 0) {
                    System.out.println("[UrkelTreeRecovery] Fast rebuild: " + count[0] + " names inserted ("
                            + (System.currentTimeMillis() - t0) / 1000 + " s)");
                }
            });
            sdb.persistNameTreeStateTimed(tip, 0);
            byte[] rebuilt = sdb.getNameTree().committedRoot();
            System.out.println("[UrkelTreeRecovery] Fast rebuild: " + count[0] + " names inserted in "
                    + (System.currentTimeMillis() - t0) / 1000 + " s, rebuilt root " + hex(rebuilt));
            if (!Arrays.equals(rebuilt, expected)) {
                String msg = "The Urkel tree is consistent with this node's names table (rebuilt root "
                        + hex(rebuilt) + "), but that root does not match the header at height " + (tip + 1)
                        + " (" + hex(expected) + "). So the NAMES TABLE itself differs from the chain's, not just "
                        + "the tree. A tree-only repair or replay cannot fix that. Compare against a correct "
                        + "node with NameStateDiff (digest / compare / detail) to find the differing names.";
                System.out.println("[UrkelTreeRecovery] " + msg);
                sdb.close();
                scratchDb = null;
                deleteDir(scratchDir);
                return new RecoveryResult(false, msg);
            }
            sdb.commit();
            swapIn(realDb, sdb);
            realDb.getNameTree().adoptRecoveredRoots(sdb.getNameTree().liveRoot(), rebuilt);
            realDb.commit();
            sdb.close();
            scratchDb = null;
            deleteDir(scratchDir);
            return new RecoveryResult(true, "Recovery succeeded -- the tree was rebuilt from the names table "
                    + "in " + (System.currentTimeMillis() - t0) / 1000 + " s and its root matches the header at "
                    + "height " + (tip + 1) + ".");
        } catch (Exception e) {
            System.out.println("[UrkelTreeRecovery] Fast rebuild failed: " + e);
            if (scratchDb != null) { try { scratchDb.close(); } catch (Exception ignore) {} }
            deleteDir(scratchDir);
            return new RecoveryResult(false, "Fast rebuild failed with an exception: " + e);
        }
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
        // RE-ARCHITECTURE: urkelNodesMapForRecovery() now returns
        // KVMap<byte[], byte[]> (see META_STORAGE_FORMAT_VERSION's own
        // comment) -- the `chunk` HashMap below is built once and only
        // ever iterated via putAll(), never looked up by key, so byte[]'s
        // identity-based equals()/hashCode() causes no correctness issue
        // here (same reasoning as UrkelNodeStore.putAll()'s own dedup
        // comment, except there's no dedup NEEDED here -- each key
        // already comes from the scratch store's own distinct node set).
        KVMap<byte[], byte[]> realNodes = realDb.urkelNodesMapForRecovery();
        KVMap<byte[], byte[]> scratchNodes = scratchDb.urkelNodesMapForRecovery();

        Map<byte[], byte[]> chunk = new HashMap<>();
        int[] copied = {0};
        // Streaming key-by-key, then a separate get() per key, not
        // entrySet() -- confirmed directly that entrySet() eagerly
        // materializes its entire result into an in-memory List before
        // returning anything, the same unsafe-at-real-scale pattern
        // this project has already had to fix more than once elsewhere.
        // Slower (two round trips per entry instead of one), but this
        // is a rare recovery path, not a hot one -- memory safety here
        // matters more than shaving off the extra round trip.
        try (KVMap.KVSnapshot<byte[]> snapshot = scratchNodes.openSnapshot()) {
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