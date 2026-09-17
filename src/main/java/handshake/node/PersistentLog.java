package handshake.node;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

/** FIX: a direct response to real, repeated cost this session -- days
 *  spent manually re-running a slow diagnostic tool, watching live
 *  console output, just to find which block a mismatch happened at.
 *  None of that needed to be lost the way it was: the information was
 *  always being printed, just never durably kept anywhere once the
 *  terminal scrolled past it or the process exited.
 *
 *  Deliberately a PLAIN FILE, not a RocksDB table, and this distinction
 *  matters: writing operational logs into the same database that might
 *  be the thing having problems creates a correlated-failure risk --
 *  if the database itself is corrupted or won't open (exactly the
 *  scenario where you'd most want to see what happened), logs
 *  describing that failure would be sitting inside the very thing you
 *  can't read. A plain file needs nothing else to be working to be
 *  readable, including RocksDB itself.
 *
 *  Deliberately narrow in scope: this is NOT a general logging
 *  framework replacing System.out/System.err everywhere in this
 *  codebase. It's specifically for the events that matter for exactly
 *  the kind of multi-day diagnostic hunt this exists to prevent: tree
 *  mismatches, backpressure emergencies, and automatic-recovery
 *  attempts and their outcomes -- rare, significant events where
 *  losing the record because nobody was watching a terminal live is
 *  the real cost. Routine, frequent activity (every block processed,
 *  every ordinary reconciliation cycle) deliberately does NOT get
 *  logged here -- that would just grow the file unboundedly for no
 *  real benefit, and bury the rare, significant lines this exists to
 *  preserve under noise.
 *
 *  Each call opens, appends, and closes the file fresh -- no buffering,
 *  no held-open file handle kept between calls. That's slightly more
 *  overhead per call than a buffered writer would have, but these
 *  events are rare (not per-block), and the whole point is durability:
 *  a call made right before a crash must actually be on disk when the
 *  next startup checks, not sitting in an in-memory buffer that dies
 *  with the process along with everything else. */
public final class PersistentLog {
    private PersistentLog() {}

    public static void logError(String dataDir, String message) {
        write(dataDir, "ERROR", message);
    }

    public static void logWarn(String dataDir, String message) {
        write(dataDir, "WARN", message);
    }

    private static void write(String dataDir, String level, String message) {
        try {
            Path logPath = Paths.get(dataDir, "node.log");
            String line = Instant.now() + " [" + level + "] " + message + System.lineSeparator();
            Files.writeString(logPath, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            // Deliberately swallowed beyond this point -- a logging
            // failure must never be what brings down block processing
            // or a diagnostic run itself; the event that triggered this
            // call is more important than the log write succeeding.
            // Still surfaced to stderr so a broken log path isn't
            // silent forever.
            System.err.println("[PersistentLog] Failed to write to node.log: " + e);
        }
    }
}