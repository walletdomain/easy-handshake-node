package handshake.node;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * Automatic, in-process diagnostic dump fired the INSTANT
 * BlockProcessor detects an Urkel tree root mismatch -- see
 * BlockProcessor's own mismatch-handling block for the call site.
 *
 * This exists to directly close the real, repeated cost this project
 * hit: an Urkel tree mismatch used to mean stopping the node, then
 * separately re-running a hand-built, manually-invoked tool
 * (InspectCommitWindow) against the database to reconstruct exactly
 * what happened -- or, before that tool existed, a multi-day
 * from-genesis replay (UrkelDivergenceFinder) just to find which block.
 * Everything either of those needed is ALREADY sitting in this process
 * at the moment the mismatch is detected: the just-downloaded blocks
 * for the whole commit window that produced the disputed root, the
 * currently-persisted state of every name that window touched, and the
 * machine's own heap/disk condition. This writes all of it to one file,
 * synchronously, before the mismatch exception ever leaves
 * BlockProcessor -- so the first time this ever happens again, the full
 * picture is already on disk by the time anyone looks, with no separate
 * tool run and no replay required.
 *
 * Deliberately reuses BlockProcessor.parseBlockTxs()/extractName()
 * rather than re-implementing covenant decoding -- the same fidelity
 * guarantee InspectCommitWindow got via reflection into those same
 * methods (see its own comment), just via a direct package-private call
 * now that this lives in production rather than being a one-off
 * external tool.
 *
 * Read-only with respect to the database: calls db.getBlock()/
 * db.getNameByHash() only. Never writes anything to ChainDB. The only
 * write this class ever performs is the plain diagnostic file itself.
 */
final class UrkelMismatchDiagnostics {
    private UrkelMismatchDiagnostics() {}

    /**
     * Writes the dump and returns the absolute path written, or null if
     * the dump itself failed (logged to stderr in that case, but never
     * thrown -- a diagnostic-writing failure must not prevent or alter
     * the mismatch halt itself, and must not mask the original
     * exception with one about the diagnostics that were only trying to
     * help explain it).
     */
    static String dump(ChainDB db, int mismatchHeight, byte[] claimedRoot,
                       byte[] computedRoot, int firstRisky) {
        int treeInterval = BlockProcessor.TREE_INTERVAL_CONST;
        String dataDir = db.getDataDir();
        // Timestamped, not overwritten -- if this ever fires more than
        // once (e.g. a retry that hits the same or a different height),
        // every occurrence's own full context is kept, not just the
        // latest.
        String fileName = "urkel-mismatch-" + mismatchHeight + "-" + Instant.now().toEpochMilli() + ".txt";
        File outFile = new File(dataDir, fileName);

        int commitHeight = mismatchHeight - 1;
        int windowStart = commitHeight - treeInterval + 1;

        try (PrintStream out = new PrintStream(new FileOutputStream(outFile), true, StandardCharsets.UTF_8)) {
            out.println("=================================================================");
            out.println("  AUTOMATIC URKEL TREE MISMATCH DIAGNOSTIC DUMP");
            out.println("  (written automatically the moment this was detected --");
            out.println("   no separate tool run or from-genesis replay was needed)");
            out.println("=================================================================");
            out.println("Generated:                       " + Instant.now());
            out.println("Mismatch detected at height:     " + mismatchHeight);
            out.println("Header at that height claims:    " + HexUtil.encode(claimedRoot));
            out.println("We had committed:                " + HexUtil.encode(computedRoot));
            out.println("Commit boundary under suspicion:  " + commitHeight
                    + "  (window " + windowStart + ".." + commitHeight
                    + ", " + treeInterval + " blocks)");
            out.println("Heap at time of failure:          " + UrkelNameTree.heapSnapshot());
            out.printf("Database directory:               %s  (%.2f GB)%n",
                    dataDir, db.getDiskSizeBytes() / 1e9);
            File dir = new File(dataDir);
            out.printf("Usable disk space on that volume: %.2f GB%n", dir.getUsableSpace() / 1e9);
            if (firstRisky != -1) {
                out.println("A deep-catch-up (unvalidated) reconciliation first deleted something "
                        + "at height " + firstRisky + " -- a plausible, known, bounded explanation "
                        + "(see UrkelTree.removeDirectly()'s own comment). UrkelTreeRecovery can "
                        + "attempt to self-correct from before that point.");
            } else {
                out.println("No deep-catch-up reconciliation has ever run in this session -- that "
                        + "known, bounded false-positive risk cannot explain this on its own.");
            }
            out.println();
            out.println("Every covenant transaction in the suspect window, decoded, followed by "
                    + "each touched name's CURRENT persisted state (after everything up through "
                    + "this database's own tip has already been applied, not a step-by-step trace):");
            out.println();

            // RE-ARCHITECTURE: the actual window walk/decode/print logic
            // now lives in CovenantDumpUtil, shared verbatim with
            // InspectCommitWindow -- see that class's own comment for why
            // (this file and InspectCommitWindow used to each carry their
            // own, nearly line-for-line identical copy of this).
            int covenantTxCount = CovenantDumpUtil.dumpWindow(out, db, windowStart, commitHeight);

            out.println();
            out.println("Total covenant transactions in window: " + covenantTxCount);
            out.println();
            out.println("Nothing above was modified or re-validated -- this is a pure, read-only "
                    + "dump of exactly what was already in this database and this process at the "
                    + "moment the mismatch was detected.");
        } catch (Exception e) {
            System.err.println("[UrkelMismatchDiagnostics] Failed to write dump file (mismatch "
                    + "handling continues regardless): " + e);
            return null;
        }
        return outFile.getAbsolutePath();
    }

}