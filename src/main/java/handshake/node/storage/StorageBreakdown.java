package handshake.node.storage;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Where the node's disk space goes, for the web admin Storage panel.
 *
 * <p>Segments (in display order): the chain database split by table -- blocks, Urkel tree nodes, UTXOs, names, undo
 * records, indexes, headers -- then "WAL &amp; other tables" (write-ahead log, manifest, small tables, files RocksDB has
 * not deleted yet), then snapshots, then "Scratch, logs &amp; other" (everything else in the data directory).
 *
 * <p>The snapshot segment counts only bytes that are NOT shared with the live database. A snapshot is a set of hard
 * links, so its files normally share storage with the live files and cost nothing; only files that compaction has since
 * replaced in the live database (the snapshot is the only thing still holding them) take real space. A file counts as
 * shared when both names point at the same file on disk (same file key); where the file system gives no key, the same
 * name and size is taken as shared.
 *
 * <p>The directory walk is cheap (hundreds of files) but the result is cached for a few seconds so a busy page cannot
 * make it run continuously.
 */
public final class StorageBreakdown {

    public record Segment(String id, String label, long bytes) { }

    public record Result(List<Segment> segments, long nodeBytes, long snapshotSharedBytes) { }

    private static final long CACHE_MILLIS = 15_000;

    private final ChainDB db;
    private final Path dataDir;
    private Result cached;
    private long cachedAt;

    public StorageBreakdown(ChainDB db, String dataDir) {
        this.db = db;
        this.dataDir = Path.of(dataDir).toAbsolutePath().normalize();
    }

    public synchronized Result get() {
        long now = System.currentTimeMillis();
        if (cached == null || now - cachedAt > CACHE_MILLIS) {
            try {
                cached = compute();
            } catch (RuntimeException e) {
                if (cached == null) throw e;
            }
            cachedAt = now;
        }
        return cached;
    }

    private Result compute() {
        Path chainDir = Path.of(db.getPath()).toAbsolutePath().normalize();
        Path snapDir = dataDir.resolve("snapshots");

        long chainTotal = dirSize(chainDir, null);

        // Per table (column family), grouped into the display segments.
        Map<String, Long> cf = db.mapSizes();
        if (cf.isEmpty() && cached != null) return cached; // database closing: keep showing the last good figures
        long blocks = 0, urkel = 0, utxos = 0, names = 0, undo = 0, indexes = 0, headers = 0, cfOther = 0;
        for (Map.Entry<String, Long> e : cf.entrySet()) {
            long v = e.getValue();
            switch (e.getKey()) {
                case "blocks", "side_blocks" -> blocks += v;
                case "urkelNodes" -> urkel += v;
                case "utxos" -> utxos += v;
                case "names" -> names += v;
                case "undo" -> undo += v;
                case "txindex", "addrtx", "addrcoin", "hashIndex" -> indexes += v;
                case "headers", "chainwork", "side_headers" -> headers += v;
                default -> cfOther += v;
            }
        }
        long cfSum = blocks + urkel + utxos + names + undo + indexes + headers + cfOther;
        // Whatever is in the database directory beyond the tables' own live files: write-ahead log, manifest,
        // options files, and obsolete files awaiting deletion.
        long dbOther = Math.max(0, chainTotal - cfSum) + cfOther;

        // Snapshots: only the bytes not shared with the live database.
        long snapOnly = 0, snapShared = 0;
        if (Files.isDirectory(snapDir)) {
            Map<String, FileInfo> live = new HashMap<>();
            listFiles(chainDir, live, true);
            Map<String, FileInfo> snap = new LinkedHashMap<>();
            listFiles(snapDir, snap, false);
            Set<Object> counted = new HashSet<>();
            for (FileInfo f : snap.values()) {
                Object id = f.key != null ? f.key : f.path;
                if (!counted.add(id)) continue; // the same file reached through two snapshot folders
                FileInfo twin = live.get(f.name);
                boolean shared = twin != null && (f.key != null && twin.key != null ? f.key.equals(twin.key) : f.size == twin.size);
                if (shared) snapShared += f.size; else snapOnly += f.size;
            }
        }

        // Everything else in the data directory (logs, scratch, config database, keys, ...).
        long rest = dirSize(dataDir, p -> p.equals(chainDir) || p.equals(snapDir));

        List<Segment> segs = new ArrayList<>();
        segs.add(new Segment("blocks", "Blocks", blocks));
        segs.add(new Segment("urkel", "Urkel tree", urkel));
        segs.add(new Segment("utxos", "UTXOs", utxos));
        segs.add(new Segment("names", "Names", names));
        segs.add(new Segment("undo", "Undo data", undo));
        segs.add(new Segment("indexes", "Indexes", indexes));
        segs.add(new Segment("headers", "Headers", headers));
        segs.add(new Segment("dbother", "WAL & other tables", dbOther));
        segs.add(new Segment("snapshots", "Snapshots (extra)", snapOnly));
        segs.add(new Segment("rest", "Scratch, logs & other", rest));

        long node = 0;
        for (Segment s : segs) node += s.bytes();
        return new Result(segs, node, snapShared);
    }

    /** The /api/status "storage" object, given the partition's free and total bytes (-1 = unknown) and its level. */
    public String toJson(long diskFree, long diskTotal) {
        Result r = get();
        StringBuilder sb = new StringBuilder("{\"segments\":[");
        boolean first = true;
        for (Segment s : r.segments()) {
            if (!first) sb.append(',');
            first = false;
            sb.append("{\"id\":\"").append(s.id()).append("\",\"label\":\"").append(s.label())
                    .append("\",\"bytes\":").append(s.bytes()).append('}');
        }
        sb.append("],\"nodeBytes\":").append(r.nodeBytes())
                .append(",\"snapshotSharedBytes\":").append(r.snapshotSharedBytes())
                .append(",\"free\":").append(diskFree)
                .append(",\"total\":").append(diskTotal).append('}');
        return sb.toString();
    }

    // ── file helpers ────────────────────────────────────────────────────────

    private record FileInfo(String name, Path path, long size, Object key) { }

    private static void listFiles(Path root, Map<String, FileInfo> out, boolean byName) {
        if (!Files.isDirectory(root)) return;
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override public FileVisitResult visitFile(Path f, BasicFileAttributes a) {
                    out.put(byName ? f.getFileName().toString() : f.toString(),
                            new FileInfo(f.getFileName().toString(), f, a.size(), a.fileKey()));
                    return FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult visitFileFailed(Path f, IOException e) { return FileVisitResult.CONTINUE; }
            });
        } catch (IOException ignored) { /* partial listing is fine for a display figure */ }
    }

    private interface Skip { boolean skip(Path p); }

    private static long dirSize(Path root, Skip skip) {
        if (!Files.isDirectory(root)) return 0;
        final long[] total = {0};
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override public FileVisitResult preVisitDirectory(Path d, BasicFileAttributes a) {
                    return skip != null && !d.equals(root) && skip.skip(d) ? FileVisitResult.SKIP_SUBTREE : FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult visitFile(Path f, BasicFileAttributes a) { total[0] += a.size(); return FileVisitResult.CONTINUE; }
                @Override public FileVisitResult visitFileFailed(Path f, IOException e) { return FileVisitResult.CONTINUE; }
            });
        } catch (IOException ignored) { /* partial total is fine for a display figure */ }
        return total[0];
    }
}
