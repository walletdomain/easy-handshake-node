package handshake.node.util;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Copies everything the node prints (System.out and System.err) into a small in-memory ring buffer,
 * so the web admin page can show a live log with scroll-back. The original streams keep working
 * exactly as before (console, journald, redirected files): this only ADDS a copy of each line.
 *
 * Memory is bounded: at most CAPACITY lines are kept and each line is cut to MAX_LINE characters.
 * Install once, as early as possible, with LogTap.install().
 */
public final class LogTap {
    private LogTap() {}

    public static final int CAPACITY = 500;
    private static final int MAX_LINE = 1000;

    public record Line(long seq, long time, boolean err, String text) {
        public String toJson() {
            return "{\"seq\":" + seq + ",\"t\":" + time + ",\"lvl\":\"" + (err ? "err" : "out")
                    + "\",\"m\":\"" + JsonUtil.escape(text) + "\"}";
        }
    }

    private static final Line[] ring = new Line[CAPACITY];
    private static long nextSeq = 1;
    private static final List<Consumer<Line>> listeners = new CopyOnWriteArrayList<>();
    private static boolean installed;

    public static synchronized void install() {
        if (installed) return;
        installed = true;
        System.setOut(new PrintStream(new Tee(System.out, false), true, StandardCharsets.UTF_8));
        System.setErr(new PrintStream(new Tee(System.err, true), true, StandardCharsets.UTF_8));
    }

    // ── Rotating log file ────────────────────────────────────────────────────

    /** One file grows to this size, then is renamed to .1 (older ones shift up); the oldest is deleted. */
    private static final long FILE_MAX_BYTES = 10L * 1024 * 1024;
    /** Files kept besides the live one: total disk use is at most (FILE_KEEP + 1) * FILE_MAX_BYTES = 50 MB. */
    private static final int FILE_KEEP = 4;
    /** Lines waiting for the writer thread. A full queue drops lines (counted) so logging can never stall the node. */
    private static final int FILE_QUEUE = 20_000;
    private static final ArrayBlockingQueue<String> fileQueue = new ArrayBlockingQueue<>(FILE_QUEUE);
    private static final AtomicLong fileDropped = new AtomicLong();
    private static boolean fileStarted;
    private static final DateTimeFormatter FILE_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS XXX");

    /**
     * Starts writing every line (the same lines the web admin shows) to dir/node-console.log, with size-capped
     * rotation. Lines printed before this call (the banner) are written first. Failure to open the file is reported
     * once to the console and never affects the node.
     */
    public static synchronized void startFile(Path dir) {
        if (fileStarted) return;
        fileStarted = true;
        long firstLive;
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            System.err.println("[LogFile] Cannot create " + dir + " (" + e + ") -- no log file will be written.");
            return;
        }
        for (Line l : snapshot()) queueLine(l);
        firstLive = nextSeq;
        addListener(l -> { if (l.seq() >= firstLive) queueLine(l); });
        Thread t = new Thread(() -> fileWriterLoop(dir.resolve("node-console.log")), "log-file-writer");
        t.setDaemon(true);
        t.start();
    }

    private static void queueLine(Line l) {
        String s = FILE_TIME.format(OffsetDateTime.ofInstant(java.time.Instant.ofEpochMilli(l.time()),
                java.time.ZoneId.systemDefault())) + (l.err() ? " E " : "   ") + l.text();
        if (!fileQueue.offer(s)) fileDropped.incrementAndGet();
    }

    private static void fileWriterLoop(Path file) {
        BufferedWriter w = null;
        long size = 0;
        List<String> batch = new ArrayList<>(512);
        while (true) {
            try {
                String first = fileQueue.poll(1, java.util.concurrent.TimeUnit.SECONDS);
                if (first == null) continue;
                batch.clear();
                batch.add(first);
                fileQueue.drainTo(batch, 2000);
                long dropped = fileDropped.getAndSet(0);
                if (dropped > 0) batch.add(FILE_TIME.format(OffsetDateTime.now()) + " E [LogFile] " + dropped
                        + " log lines were dropped because the file writer fell behind.");
                if (w == null) {
                    size = Files.exists(file) ? Files.size(file) : 0;
                    w = Files.newBufferedWriter(file, StandardCharsets.UTF_8,
                            StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                }
                for (String line : batch) {
                    w.write(line);
                    w.newLine();
                    size += line.length() + 1;
                }
                w.flush();
                if (size >= FILE_MAX_BYTES) {
                    w.close();
                    w = null;
                    rotate(file);
                    size = 0;
                }
            } catch (InterruptedException e) {
                return;
            } catch (Throwable e) {
                // Never let the log file take anything down; close it and try again on the next batch.
                try { if (w != null) w.close(); } catch (IOException ignored) { }
                w = null;
                try { Thread.sleep(5000); } catch (InterruptedException ie) { return; }
            }
        }
    }

    private static void rotate(Path file) throws IOException {
        Path dir = file.getParent();
        String name = file.getFileName().toString();
        Files.deleteIfExists(dir.resolve(name + "." + FILE_KEEP));
        for (int i = FILE_KEEP - 1; i >= 1; i--) {
            Path from = dir.resolve(name + "." + i);
            if (Files.exists(from)) Files.move(from, dir.resolve(name + "." + (i + 1)), StandardCopyOption.REPLACE_EXISTING);
        }
        Files.move(file, dir.resolve(name + ".1"), StandardCopyOption.REPLACE_EXISTING);
    }

    /** The newest lines, oldest first. */
    public static synchronized List<Line> snapshot() {
        List<Line> out = new ArrayList<>(CAPACITY);
        long first = Math.max(1, nextSeq - CAPACITY);
        for (long s = first; s < nextSeq; s++) {
            Line l = ring[(int) (s % CAPACITY)];
            if (l != null && l.seq() == s) out.add(l);
        }
        return out;
    }

    public static void addListener(Consumer<Line> l) { listeners.add(l); }
    public static void removeListener(Consumer<Line> l) { listeners.remove(l); }

    private static void add(boolean err, String text) {
        if (text.length() > MAX_LINE) text = text.substring(0, MAX_LINE) + " ...";
        Line line;
        synchronized (LogTap.class) {
            line = new Line(nextSeq, System.currentTimeMillis(), err, text);
            ring[(int) (nextSeq % CAPACITY)] = line;
            nextSeq++;
        }
        for (Consumer<Line> l : listeners) {
            try { l.accept(line); } catch (Throwable ignored) { /* a bad listener must never break logging */ }
        }
    }

    /** Passes bytes through untouched and assembles complete lines for the ring buffer. */
    private static final class Tee extends OutputStream {
        private final PrintStream original;
        private final boolean err;
        private final ByteArrayOutputStream pending = new ByteArrayOutputStream();

        Tee(PrintStream original, boolean err) { this.original = original; this.err = err; }

        @Override public void write(int b) {
            original.write(b);
            collect(b);
        }

        @Override public void write(byte[] b, int off, int len) {
            original.write(b, off, len);
            for (int i = 0; i < len; i++) collect(b[off + i]);
        }

        @Override public void flush() { original.flush(); }

        private synchronized void collect(int b) {
            if (b == '\n') {
                String s = pending.toString(StandardCharsets.UTF_8);
                pending.reset();
                if (s.endsWith("\r")) s = s.substring(0, s.length() - 1);
                if (!s.isEmpty()) add(err, s);
            } else if (pending.size() < MAX_LINE * 4) {
                pending.write(b);
            }
        }
    }
}
