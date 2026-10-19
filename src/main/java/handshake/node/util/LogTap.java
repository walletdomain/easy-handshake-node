package handshake.node.util;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
