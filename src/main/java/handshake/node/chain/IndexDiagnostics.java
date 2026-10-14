package handshake.node.chain;

import handshake.node.NodeConfig;
import handshake.node.storage.ChainDB;
import handshake.node.storage.PersistentLog;
import handshake.node.util.HexUtil;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.management.*;
import java.nio.file.*;
import java.util.*;

/**
 * Writes one self-contained file with everything needed to understand an index problem without re-running
 * anything: what failed, where in the chain, the data involved, the state of the index and the chain, and the
 * JVM/RocksDB memory picture. Files are bounded in size and rate-limited so a systematic failure cannot fill
 * the disk or the log.
 */
public final class IndexDiagnostics {
    private IndexDiagnostics() {}

    private static final int MAX_FILES_PER_RUN = 5;
    private static int written = 0;

    public static synchronized String dump(ChainDB db, String title, Throwable t, Map<String, Object> ctx, List<String> lines) {
        String msg = "[Index] " + title + (t != null ? " -- " + t : "");
        System.err.println(msg);
        try { PersistentLog.logError(db.getDataDir(), msg); } catch (Throwable ignore) { }
        if (written >= MAX_FILES_PER_RUN) return null;
        written++;
        StringBuilder sb = new StringBuilder(8192);
        sb.append("INDEX DIAGNOSTIC\n================\n");
        sb.append("when:    ").append(new Date()).append('\n');
        sb.append("node:    ").append(NodeConfig.VERSION).append("  java ").append(System.getProperty("java.version")).append('\n');
        sb.append("problem: ").append(title).append("\n\n");

        sb.append("-- context --\n");
        if (ctx != null) for (var e : ctx.entrySet()) sb.append(String.format("%-22s %s%n", e.getKey(), e.getValue()));

        sb.append("\n-- chain / index state --\n");
        try {
            sb.append("block tip:             ").append(db.getBlockTip()).append('\n');
            sb.append("header tip:            ").append(db.getHeaderTip()).append('\n');
            sb.append("index height:          ").append(db.getIndexHeight()).append('\n');
            sb.append("address index enabled: ").append(db.addressIndexEnabled()).append('\n');
            sb.append("addr_index_complete:   ").append(db.getMeta("addr_index_complete")).append('\n');
            if (db.index() != null) sb.append("index stats:           ").append(db.index().stats()).append('\n');
        } catch (Throwable e) { sb.append("(state unavailable: ").append(e).append(")\n"); }

        sb.append("\n-- memory --\n").append(memoryReport());

        if (lines != null && !lines.isEmpty()) {
            sb.append("\n-- detail (").append(lines.size()).append(" lines") .append(lines.size() >= 200 ? ", truncated" : "").append(") --\n");
            int n = 0;
            for (String l : lines) { sb.append(l).append('\n'); if (++n >= 200) break; }
        }
        if (t != null) {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            sb.append("\n-- stack trace --\n").append(sw);
        }
        sb.append("\n-- what to send --\nThis whole file. If the problem is a block, also its height (above).\n");
        try {
            Path p = Paths.get(db.getDataDir(), "index-diagnostic-" + System.currentTimeMillis() + ".txt");
            Files.writeString(p, sb.toString());
            System.err.println("[Index] Full diagnostic written to: " + p);
            return p.toString();
        } catch (Throwable e) {
            System.err.println("[Index] could not write diagnostic file: " + e);
            System.err.println(sb);
            return null;
        }
    }

    public static String memoryReport() {
        StringBuilder sb = new StringBuilder();
        Runtime rt = Runtime.getRuntime();
        long mb = 1024 * 1024;
        sb.append(String.format("heap used %d MB / committed %d MB / max %d MB%n",
                (rt.totalMemory() - rt.freeMemory()) / mb, rt.totalMemory() / mb, rt.maxMemory() / mb));
        for (MemoryPoolMXBean p : ManagementFactory.getMemoryPoolMXBeans()) {
            MemoryUsage u = p.getUsage();
            if (u != null) sb.append(String.format("  pool %-28s used %d MB%n", p.getName(), u.getUsed() / mb));
        }
        for (GarbageCollectorMXBean g : ManagementFactory.getGarbageCollectorMXBeans())
            sb.append(String.format("  gc %-24s count=%d time=%dms%n", g.getName(), g.getCollectionCount(), g.getCollectionTime()));
        sb.append("threads: ").append(ManagementFactory.getThreadMXBean().getThreadCount()).append('\n');
        return sb.toString();
    }

    public static String hex(byte[] b) { return b == null ? "null" : HexUtil.encode(b); }
}