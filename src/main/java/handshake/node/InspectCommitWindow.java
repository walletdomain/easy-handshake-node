package handshake.node;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * ONE-OFF, MANUAL-USE-ONLY diagnostic tool. Not wired into Main.java,
 * not part of a distributed build.
 *
 * Purpose: produce a complete, decoded audit trail of every covenant
 * transaction in the ONE 36-block commit window whose combined effect
 * produced the Urkel root that height 210277's real header disagrees
 * with -- rather than re-running another multi-day, from-genesis
 * replay that would only reconfirm a mismatch already reproduced four
 * times with identical claimed/computed roots.
 *
 * Deliberately does NOT re-implement any covenant business logic -- the
 * actual window walk/decode/print logic lives in the shared
 * CovenantDumpUtil (also used by the automatic UrkelMismatchDiagnostics
 * dump), which calls directly into BlockProcessor's own package-private
 * extractName()/parseBlockTxs() helpers, so this tool's output can never
 * drift from what the real validator actually believes about a given
 * transaction. (This used to reach extractName() via reflection, back
 * when it was still private -- no longer needed now that it's
 * package-private and CovenantDumpUtil can just call it directly.)
 *
 * Opens the real database READ-ONLY (see ChainDB.openReadOnly()'s own
 * comment on why that's safe even alongside a live node) and never
 * writes anything, anywhere. Safe to run at any time, repeatedly,
 * without threatening the real database in any way.
 *
 * Usage (no arguments needed -- both are hard-coded below):
 *   java -cp <classpath> handshake.node.InspectCommitWindow
 *
 * Optionally still overridable from the command line, in case this ever
 * needs to run against a different data directory or a different commit
 * boundary without editing the source:
 *   java -cp <classpath> handshake.node.InspectCommitWindow <dataDir> [commitHeight]
 *
 * DEFAULT_COMMIT_HEIGHT is 210276 -- the last TREE_INTERVAL boundary
 * (36-block commit) before the height-210277 mismatch. Prints every
 * covenant transaction in the window (commitHeight-35 .. commitHeight),
 * plus the currently-stored committed root and (if already locally
 * available via header-first sync) height 210277's own claimed root,
 * for direct side-by-side comparison.
 */
public class InspectCommitWindow {

    private static final int TREE_INTERVAL = 36;

    // Hard-coded defaults -- same convention as UrkelDivergenceFinder's
    // own DEFAULT_DATA_DIR, for exactly the same reason: safe to just
    // run with no arguments (e.g. IntelliJ's Run button), which doesn't
    // pass program arguments unless a run configuration is explicitly
    // set up for them.
    private static final String DEFAULT_DATA_DIR = "C:\\Users\\florc\\.easy-handshake-node";
    private static final int DEFAULT_COMMIT_HEIGHT = 210276;

    // FIX: a real, reported problem -- IntelliJ's own Run window has a
    // finite scroll-back buffer, and this tool's output (thousands of
    // covenant transactions for a busy window) blew straight past it,
    // silently losing the earliest lines -- specifically the handful of
    // header/summary lines printed right at the top (the committed root
    // currently on disk, height 210277's own claimed root, and whether
    // they match), which are the single most load-bearing lines this
    // tool produces. Writing directly to a file sidesteps any console
    // buffer entirely -- nothing here is lost regardless of how much
    // this prints. System.out is redirected wholesale, right here,
    // before anything else runs, so every existing println/printf call
    // below needs no changes at all to end up in the file instead.
    private static final String OUTPUT_FILE_NAME = "InspectCommitWindow-output.txt";

    public static void main(String[] args) throws Exception {
        String dataDir = args.length >= 1 ? args[0] : DEFAULT_DATA_DIR;
        int commitHeight = args.length >= 2 ? Integer.parseInt(args[1]) : DEFAULT_COMMIT_HEIGHT;
        int windowStart = commitHeight - TREE_INTERVAL + 1;

        java.io.File outputFile = new java.io.File(dataDir, OUTPUT_FILE_NAME);
        PrintStream realConsole = System.out;
        PrintStream fileOut = new PrintStream(
                new java.io.FileOutputStream(outputFile), true, StandardCharsets.UTF_8);
        System.setOut(fileOut);

        // Deliberately still printed to the REAL console (not the
        // redirected one) -- the one thing worth seeing immediately,
        // without having to open the file first.
        realConsole.println("Writing all output to: " + outputFile.getAbsolutePath());
        realConsole.println("(Nothing further will appear in this console window -- open that "
                + "file once this finishes, or tail it while it runs.)");

        if (args.length == 0) {
            System.out.println("No arguments given -- using the hard-coded defaults "
                    + "(see DEFAULT_DATA_DIR / DEFAULT_COMMIT_HEIGHT at the top of this file).");
        }

        if (commitHeight % TREE_INTERVAL != 0) {
            System.out.println("WARNING: height " + commitHeight + " is not itself a "
                    + TREE_INTERVAL + "-block commit boundary (" + commitHeight + " % "
                    + TREE_INTERVAL + " = " + (commitHeight % TREE_INTERVAL) + "). "
                    + "Proceeding anyway, but the printed window may not line up with a "
                    + "real commit the way it does for the default height.");
        }

        System.out.println("=================================================================");
        System.out.println("  COMMIT WINDOW INSPECTOR -- ONE-OFF DIAGNOSTIC TOOL");
        System.out.println("=================================================================");
        System.out.println("Database (read-only): " + dataDir);
        System.out.println("Commit boundary height: " + commitHeight);
        System.out.println("Window: " + windowStart + " .. " + commitHeight
                + " (" + TREE_INTERVAL + " blocks)");
        System.out.println();

        ChainDB db = ChainDB.openReadOnly(dataDir + "/chain.mv.db");

        // RE-ARCHITECTURE: this used to reach BlockProcessor.extractName()
        // via reflection (getDeclaredMethod + setAccessible(true)), the
        // same workaround UrkelDivergenceFinder used, because the method
        // was private at the time. It has since been made package-private
        // specifically so UrkelMismatchDiagnostics (now, also
        // CovenantDumpUtil below) could call it directly -- which this
        // class, being in the same package, can do too. The reflection
        // was never actually needed anymore; a direct call is simpler,
        // faster, and cannot throw a reflection-specific exception the
        // original try/catch around the invoke() call wasn't really
        // written to distinguish from a real extraction failure.
        byte[] committedRoot = db.getNameTree().committedRoot();
        System.out.println("Committed root currently stored in this database: "
                + hex(committedRoot));

        int nextHeight = commitHeight + 1;
        byte[] nextHeader = db.getHeader(nextHeight);
        if (nextHeader != null) {
            byte[] claimedRoot = HeaderUtil.treeRoot(
                    java.util.Arrays.copyOf(nextHeader, Math.min(236, nextHeader.length)));
            System.out.println("Header at height " + nextHeight + " (already available locally "
                    + "via header-first sync) claims tree root: " + hex(claimedRoot));
            System.out.println("MATCH with currently-stored committed root: "
                    + java.util.Arrays.equals(claimedRoot, committedRoot));
        } else {
            System.out.println("No locally stored header at height " + nextHeight
                    + " -- cannot cross-check against it here.");
        }
        System.out.println();

        // RE-ARCHITECTURE: the actual window walk/decode/print logic now
        // lives in CovenantDumpUtil, shared verbatim with
        // UrkelMismatchDiagnostics -- see that class's own comment for
        // why (this file and UrkelMismatchDiagnostics used to each carry
        // their own, nearly line-for-line identical copy of this).
        int covenantTxCount = CovenantDumpUtil.dumpWindow(System.out, db, windowStart, commitHeight);

        System.out.println();
        System.out.println("Total covenant transactions in window: " + covenantTxCount);
        System.out.println();
        System.out.println("Nothing above was modified or re-validated -- this is a pure, "
                + "read-only dump of exactly what's already on disk, decoded for inspection.");

        fileOut.flush();
        fileOut.close();
        System.setOut(realConsole);
        realConsole.println("Done -- wrote " + covenantTxCount + " covenant transactions to: "
                + outputFile.getAbsolutePath());
    }

    // RE-ARCHITECTURE: printCovenant()/covenantTypeName() used to live
    // here (and, separately, as a near-identical copy in
    // UrkelMismatchDiagnostics) -- both now delegate to the single
    // shared CovenantDumpUtil.dumpWindow() call above. See that class's
    // own comment for why.

    private static String hex(byte[] b) {
        return HexUtil.encode(b);
    }
}