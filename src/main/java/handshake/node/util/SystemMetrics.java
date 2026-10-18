package handshake.node.util;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;

/**
 * Cheap, dependency-free host/process metrics for the web admin panel and the
 * disk-space guard. Everything here uses the JDK only (no native code).
 *
 * CPU: com.sun.management.OperatingSystemMXBean. getProcessCpuLoad() is the share of ALL
 * cores this JVM used since the previous call (0..1); it returns a negative value on the
 * very first call or if unsupported, which is reported as "unknown" (-1).
 * Memory: JVM heap used/max, plus the machine's physical memory (total/free) when the JDK
 * exposes it. Disk: usable/total bytes of the partition holding the data directory
 * (File.getUsableSpace = what this process may actually still write).
 */
public final class SystemMetrics {

    public enum DiskLevel { OK, LOW, CRITICAL }

    /** Below this the admin panel shows a warning banner. */
    public static final long DISK_LOW_BYTES = 10L * 1024 * 1024 * 1024;
    /** Below this the node shuts down cleanly rather than risk a failed RocksDB write. */
    public static final long DISK_CRITICAL_BYTES = 2L * 1024 * 1024 * 1024;

    private final File dataDir;

    public SystemMetrics(String dataDir) { this.dataDir = new File(dataDir); }

    public record Snapshot(double processCpu, double systemCpu,
                           long heapUsed, long heapMax,
                           long physTotal, long physFree,
                           long diskUsable, long diskTotal, DiskLevel diskLevel) { }

    public Snapshot snapshot() {
        double proc = -1, sys = -1; long physTotal = -1, physFree = -1;
        try {
            if (ManagementFactory.getOperatingSystemMXBean() instanceof com.sun.management.OperatingSystemMXBean os) {
                proc = os.getProcessCpuLoad();
                sys = os.getCpuLoad();
                physTotal = os.getTotalMemorySize();
                physFree = os.getFreeMemorySize();
            }
        } catch (Throwable ignored) { /* unsupported platform: report unknown */ }
        MemoryMXBean mem = ManagementFactory.getMemoryMXBean();
        long used = mem.getHeapMemoryUsage().getUsed();
        long max = mem.getHeapMemoryUsage().getMax();
        long usable = diskUsable(), total = existingAncestor().getTotalSpace();
        return new Snapshot(proc, sys, used, max, physTotal, physFree, usable, total, level(usable));
    }

    /** Usable bytes on the data directory's partition; walks up to an existing parent if needed. */
    public long diskUsable() {
        File f = existingAncestor();
        return f == null ? -1 : f.getUsableSpace();
    }

    private File existingAncestor() {
        File f = dataDir.getAbsoluteFile();
        while (f != null && !f.exists()) f = f.getParentFile();
        return f == null ? dataDir : f;
    }

    public static DiskLevel level(long usable) {
        if (usable < 0) return DiskLevel.OK;               // unknown: never trigger a shutdown on a failed query
        if (usable < DISK_CRITICAL_BYTES) return DiskLevel.CRITICAL;
        if (usable < DISK_LOW_BYTES) return DiskLevel.LOW;
        return DiskLevel.OK;
    }
}
