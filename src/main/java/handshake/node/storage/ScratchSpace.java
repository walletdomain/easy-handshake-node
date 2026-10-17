package handshake.node.storage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Where the node keeps its short-lived scratch databases (the Urkel orphan
 * queue and the reachable-hash set).
 *
 * These used to be created in the operating system's temp directory
 * (java.io.tmpdir, normally /tmp). On many servers /tmp is a small or
 * RAM-backed filesystem, and a full node sync needs gigabytes of scratch
 * space, so the node could run out of space there ("No space left on
 * device") and fail in ways the user could not be expected to diagnose.
 * The scratch area now lives inside the node's own data directory, next to
 * the chain database, so it uses the same disk the user already gave the
 * node and no operating-system setting needs to be changed.
 *
 * Main calls {@link #init(Path)} once at startup, after the data-directory
 * lock is held (so no other node can be using the folder). Anything left
 * there by a crashed run is deleted at that point. If init was never called
 * (stand-alone tools, tests), the old behaviour (system temp directory) is
 * used.
 */
public final class ScratchSpace {
    private ScratchSpace() {}

    private static volatile Path baseDir;

    /** Warn when the scratch disk has less free space than this. */
    private static final long LOW_SPACE_BYTES = 10L * 1024 * 1024 * 1024;

    public static void init(Path dir) {
        try {
            Files.createDirectories(dir);
            // Leftovers from a crashed or killed run: nothing can be using them now.
            java.io.File[] old = dir.toFile().listFiles();
            int removed = 0;
            if (old != null) {
                for (java.io.File f : old) {
                    if (f.isDirectory()) DiskBackedHashKeyStoreBase.deleteRecursive(f); else f.delete();
                    removed++;
                }
            }
            baseDir = dir;
            long free = dir.toFile().getUsableSpace();
            System.out.printf("[Scratch] Scratch directory: %s (%.1f GB free)%s%n",
                    dir.toAbsolutePath(), free / 1e9,
                    removed > 0 ? ", removed " + removed + " leftover item(s) from an earlier run" : "");
            if (free < LOW_SPACE_BYTES) {
                System.err.printf("[Scratch] WARNING: only %.1f GB free on the disk holding the node's data. "
                        + "Syncing needs several GB of scratch space; free up disk space.%n", free / 1e9);
            }
        } catch (IOException | RuntimeException e) {
            System.err.println("[Scratch] Could not prepare " + dir + " (" + e
                    + ") -- falling back to the system temp directory.");
            baseDir = null;
        }
    }

    /** Creates a fresh, uniquely named scratch directory with the given name prefix. */
    static Path newDirectory(String prefix) throws IOException {
        Path base = baseDir;
        if (base != null) {
            Files.createDirectories(base);
            return Files.createTempDirectory(base, prefix);
        }
        return Files.createTempDirectory(prefix);
    }
}
