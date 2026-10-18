package handshake.node.storage;

import handshake.node.util.SystemMetrics;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/**
 * Verified snapshots of the chain database: RocksDB checkpoints (hard links, so the cost is
 * a memtable flush plus a directory of links, not a copy) taken only when the database has
 * just been proven consistent -- the committed Urkel root equals the root in the header after
 * its boundary (ChainDB.checkCommittedRoot). If corruption is ever detected and the fast
 * tree rebuild cannot fix it, the node restores the newest snapshot and re-syncs a few
 * thousand blocks instead of starting from genesis.
 *
 * Layout: &lt;dataDir&gt;/snapshots/snap-&lt;height&gt; (complete) and snap-&lt;height&gt;.tmp (being written;
 * ignored and cleaned up). Only ONE complete snapshot is kept: a snapshot pins every file that
 * existed when it was taken, so on a small disk each extra one can cost up to a full database.
 * A new snapshot is only taken when plenty of disk is free, and the disk guard deletes it first
 * when space runs low.
 *
 * Restore is done at STARTUP, before the database is opened, triggered by a flag file
 * (restore-snapshot.flag) that the node writes just before it exits on an unrecoverable
 * inconsistency. The damaged database is renamed aside, never deleted before the swap.
 */
public final class SnapshotManager {

    public static final int INTERVAL_BLOCKS = 10_000;
    public static final String FLAG_FILE = "restore-snapshot.flag";
    private static final String PREFIX = "snap-";

    private final File dataDir;
    private final File snapDir;
    private volatile int lastSnapshotHeight;

    public SnapshotManager(String dataDir) {
        this.dataDir = new File(dataDir);
        this.snapDir = new File(this.dataDir, "snapshots");
        cleanTemp();
        this.lastSnapshotHeight = latestHeight(snapDir);
    }

    public int lastSnapshotHeight() { return lastSnapshotHeight; }

    public boolean hasSnapshot() { return lastSnapshotHeight >= 0; }

    /** Called between blocks, outside any block batch. Never throws. */
    public void maybeSnapshot(ChainDB db, int height) {
        try {
            if (height % 36 != 1) return;                                      // committed root at height-1 is verified by header(height)
            if (height - Math.max(lastSnapshotHeight, 0) < INTERVAL_BLOCKS) return;
            if (db.blockBatchOpen() || db.hasPendingNameWrites()) return;
            long usable = new SystemMetrics(dataDir.getPath()).diskUsable();
            if (usable >= 0 && usable < db.getDiskSizeBytes() + SystemMetrics.DISK_LOW_BYTES) {
                System.out.println("[Snapshot] Skipping snapshot at height " + height + ": not enough free disk space for it.");
                return;
            }
            ChainDB.RootCheck check = db.checkCommittedRoot();
            if (check == null || !check.matches()) return;                     // only verified state is worth keeping
            create(db, height);
        } catch (Throwable t) {
            System.err.println("[Snapshot] Snapshot at height " + height + " failed (node continues): " + t);
        }
    }

    private void create(ChainDB db, int height) throws IOException {
        long t0 = System.currentTimeMillis();
        File tmp = new File(snapDir, PREFIX + height + ".tmp");
        deleteTree(tmp);
        Files.createDirectories(snapDir.toPath());
        db.commit();                                                          // WAL + (atomic) flush before the checkpoint
        db.createCheckpoint(tmp.getPath());
        File fin = new File(snapDir, PREFIX + height);
        Files.move(tmp.toPath(), fin.toPath(), StandardCopyOption.ATOMIC_MOVE);
        int old = lastSnapshotHeight;
        lastSnapshotHeight = height;
        if (old >= 0 && old != height) deleteTree(new File(snapDir, PREFIX + old));
        System.out.printf("[Snapshot] Verified snapshot saved at height %d (%d ms).%n", height, System.currentTimeMillis() - t0);
    }

    /** Frees disk space: removes every snapshot. Used by the disk guard. */
    public void deleteAll() {
        deleteTree(snapDir);
        lastSnapshotHeight = -1;
    }

    /** Writes the restore flag; the next startup restores the newest snapshot. */
    public static boolean requestRestore(String dataDir) {
        try {
            if (latestHeight(new File(dataDir, "snapshots")) < 0) return false;
            Files.writeString(Path.of(dataDir, FLAG_FILE), "restore newest verified snapshot\n");
            return true;
        } catch (IOException e) { return false; }
    }

    /**
     * Startup, BEFORE the database is opened. If the flag file exists, replaces the live database
     * with the newest snapshot. Returns a human-readable line when something was done or went
     * wrong, null when there was nothing to do.
     */
    public static String restoreIfRequested(String dataDir, String dbPath) {
        File flag = new File(dataDir, FLAG_FILE);
        if (!flag.exists()) return null;
        File snaps = new File(dataDir, "snapshots");
        int h = latestHeight(snaps);
        flag.delete();                                                         // never loop: one attempt per request
        if (h < 0) return "Restore was requested but no snapshot exists; continuing with the current database.";
        File snap = new File(snaps, PREFIX + h);
        File live = new File(dbPath);
        File aside = new File(dataDir, live.getName() + ".corrupt");
        try {
            deleteTree(aside);                                                 // only the previous aside copy
            if (live.exists()) Files.move(live.toPath(), aside.toPath(), StandardCopyOption.ATOMIC_MOVE);
            Files.move(snap.toPath(), live.toPath(), StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            return "Snapshot restore FAILED (" + e + "); the node was left as it was. Rename " + snap
                    + " over " + live + " manually if needed.";
        }
        deleteTree(aside);                                                     // damaged copy is of no further use; frees disk
        return "Restored the verified snapshot from height " + h + ". Sync will resume from there.";
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    static int latestHeight(File dir) {
        File[] fs = dir.listFiles();
        int best = -1;
        if (fs != null) for (File f : fs) {
            String n = f.getName();
            if (!f.isDirectory() || !n.startsWith(PREFIX) || n.endsWith(".tmp")) continue;
            try { best = Math.max(best, Integer.parseInt(n.substring(PREFIX.length()))); } catch (NumberFormatException ignored) { }
        }
        return best;
    }

    private void cleanTemp() {
        File[] fs = snapDir.listFiles();
        if (fs != null) for (File f : fs) if (f.getName().endsWith(".tmp")) deleteTree(f);
    }

    static void deleteTree(File f) {
        if (f == null || !f.exists()) return;
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteTree(k);
        f.delete();
    }
}
