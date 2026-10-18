package handshake.node.storage;

import org.rocksdb.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;

/**
 * KVStore backed by RocksDB. Each named map (see KVStore's own javadoc
 * on why there are four typed variants) becomes a RocksDB column
 * family -- RocksDB's own equivalent of MVStore's separately-named
 * maps within one file.
 *
 * Column families, unlike MVStore's maps, aren't inherently lazy: a
 * fresh RocksDB.open() call needs to know every column family that
 * will ever be touched, upfront. Handled here by discovering whatever
 * column families already exist on disk at open time (via
 * RocksDB.listColumnFamilies()), then creating any NEW one on demand,
 * on the already-open handle, the first time this project's own code
 * asks for a map name that isn't among them yet (confirmed directly,
 * via a real compile-and-run test against the actual RocksDB API,
 * that db.createColumnFamily() on an already-open RocksDB instance
 * works exactly this way) -- this preserves the same "open whatever
 * map you need, whenever you need it" behavior MVStoreKVStore already
 * has, without ChainDB needing to know or declare its own map names
 * anywhere but where it already does.
 *
 * RE-ARCHITECTURE: narrowed from public to package-private as part of
 * the handshake.node.storage split (package-reorg-plan.md, Phase 1) --
 * confirmed by a full-codebase audit that nothing outside this package
 * ever constructed or referenced this class directly; everything goes
 * through KVStore/ChainDB/ConfigDB instead. Previously public visibility
 * only held that line by convention; now that this class has its own
 * package, the compiler enforces it: a future storage-engine swap can
 * never again be bypassed from outside handshake.node.storage.
 */
class RocksDBKVStore implements KVStore {

    // FIX: RocksDB's own internal memory (memtables, block cache) is
    // NATIVE, off-heap memory -- entirely separate from and unbounded
    // by the JVM's own -Xmx limit. Previously every column family used
    // RocksDB's untuned defaults (~64MB write buffer x up to 2 buffers
    // each, no explicit block cache at all) -- across this project's 9
    // column families, that's over 1GB of unconfigured native memory a
    // low-memory machine has no visibility into and no way to bound via
    // -Xmx alone. These constants are the actual, single place to
    // adjust the tradeoff between memory footprint and performance --
    // deliberately kept as named, documented constants rather than
    // buried inline, since different users' hardware constraints are a
    // real, expected reason to want to change them.
    //
    // SECOND FIX, applied immediately after the first: an earlier
    // version of this applied WRITE_BUFFER_SIZE_BYTES uniformly to
    // every column family, including "urkelNodes" -- which, by a huge
    // margin, has the highest write volume of all 9 (every single
    // Urkel tree node write goes through it; this is the same column
    // family the persistBlock() batching fix was built for). A buffer
    // 4x smaller than RocksDB's own default meant ~4x more frequent
    // memtable flushes for that one column family specifically, which
    // meant RocksDB's own background compaction (genuinely CPU-
    // intensive: decompressing and re-merging SST files) kicked in far
    // more aggressively than before -- confirmed as the real,
    // identified cause of a real, reported CPU/GC regression, not
    // theoretical. "urkelNodes" now keeps a write buffer close to
    // RocksDB's own original default; every other column family (low
    // write volume: headers/blocks/chainwork/utxos/names/meta/peers/
    // hashIndex) stays at the smaller, memory-conscious size -- this
    // still bounds 8 of 9 column families' memory far below the
    // original, fully-untuned defaults, without starving the one that
    // genuinely needs more room to avoid thrashing.
    // FIX: was a fixed 128MB regardless of the actual machine this
    // runs on -- deliberately conservative for a modest machine, but
    // leaving real, available headroom unused on a more capable one.
    // Now scales with actual detected physical RAM: 10% of total,
    // floored at 256MB (so even a genuinely low-memory machine still
    // gets a real, functional cache, not something so small it barely
    // helps) and capped at 4GB (so a very large machine doesn't end up
    // with an oversized cache for what a block cache actually needs --
    // diminishing returns well before that point for this specific
    // workload). Detected via com.sun.management.OperatingSystemMXBean,
    // confirmed directly to work correctly (via a real compile-and-run
    // test, not assumed) rather than the JVM's own -Xmx ceiling, which
    // reports the heap limit, not total system memory. Falls back to
    // the old 128MB default if detection fails for any reason (e.g. a
    // non-HotSpot JVM that doesn't implement this interface) --
    // detection failing should never be fatal for something this
    // secondary.
    /** Total physical RAM in bytes, or -1 if it cannot be detected. */
    private static long physicalMemoryBytes() {
        try {
            return ((com.sun.management.OperatingSystemMXBean) java.lang.management.ManagementFactory.getOperatingSystemMXBean())
                    .getTotalMemorySize();
        } catch (Exception | LinkageError e) { return -1; }
    }

    /** Memory tier for the write buffers: 2 = 12 GiB or more (full size), 1 = 6 to 12 GiB (half), 0 = under 6 GiB or
     *  unknown (the original small buffers). The big buffers cut disk writes but cost up to ~1.5 GB of native memory,
     *  which a small server cannot spare next to the Java heap and the block cache. */
    private static final int MEMORY_TIER = physicalMemoryBytes() >= 12L << 30 ? 2 : physicalMemoryBytes() >= 6L << 30 ? 1 : 0;

    private static long detectSharedBlockCacheBytes() {
        long floor = 256L * 1024 * 1024;
        long ceiling = 8L * 1024 * 1024 * 1024;
        try {
            var osBean = (com.sun.management.OperatingSystemMXBean)
                    java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            long totalPhysical = osBean.getTotalMemorySize();
            long tenPercent = MEMORY_TIER == 2 ? totalPhysical / 4 : totalPhysical / 10;   // a quarter of RAM on a big machine: tree-path and UTXO reads served from memory
            return Math.max(floor, Math.min(tenPercent, ceiling));
        } catch (Exception | LinkageError e) {
            System.out.println("[RocksDBKVStore] Could not detect physical memory ("
                    + e.getClass().getSimpleName() + ") -- using the 128MB fallback for the shared block cache.");
            return 128L * 1024 * 1024;
        }
    }

    private static final long DEFAULT_WRITE_BUFFER_SIZE_BYTES = 16L * 1024 * 1024;  // 16MB per memtable for low-write-volume column families
    private static final long HIGH_VOLUME_WRITE_BUFFER_SIZE_BYTES = (MEMORY_TIER == 2 ? 256L : MEMORY_TIER == 1 ? 128L : 64L) * 1024 * 1024; // 64MB for "urkelNodes" specifically -- close to RocksDB's own original default
    private static final String HIGH_VOLUME_COLUMN_FAMILY = "urkelNodes";
    private static final long INDEX_WRITE_BUFFER_SIZE_BYTES = 32L * 1024 * 1024;  // tx/address index column families: heavy sequential-ish writes during sync
    /** utxos and names also churn (entries updated and spent again within a few blocks): a bigger memtable lets
     *  most of that cancel out in memory instead of being written to disk and compacted later. */
    private static final long CHURN_WRITE_BUFFER_SIZE_BYTES = (MEMORY_TIER == 2 ? 128L : MEMORY_TIER == 1 ? 64L : 16L) * 1024 * 1024;
    private static boolean isChurnFamily(String n) { return n.equals("utxos") || n.equals("names"); }
    private static boolean isIndexFamily(String n) { return n.equals("txindex") || n.equals("addrtx") || n.equals("addrcoin"); }
    private static final int MAX_WRITE_BUFFER_NUMBER = 2;                      // RocksDB's own default -- kept, not reduced further, since going lower would force more frequent flushes and hurt write throughput for little further memory benefit

    private final RocksDB db;
    private final BatchContext batchCtx;
    private final DBOptions dbOptions;
    private final String path;
    private final boolean readOnly;
    private final Map<String, ColumnFamilyHandle> handles = new HashMap<>();
    private final List<ColumnFamilyOptions> openedCfOptions = new ArrayList<>();
    private final Cache sharedBlockCache;
    private final Statistics statistics;
    private final boolean countAsScratch;
    /** Per column family compaction totals, fed by RocksDB's own "compaction finished" callback:
     *  {jobs, jobsFromLevel0, inputBytes, outputBytes, recordsReplaced, tombstonesSeen, micros}. */
    private final java.util.concurrent.ConcurrentHashMap<String, long[]> compactionByFamily = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, long[]> compactionReported = new HashMap<>();
    private final List<AbstractNativeReference> filterPolicies = new ArrayList<>();

    public RocksDBKVStore(String path) {
        this(path, false);
    }

    /** readOnly=true opens via RocksDB.openReadOnly() instead of the
     *  normal RocksDB.open() -- confirmed directly, via a real
     *  compile-and-run test against the actual RocksDB API, that this
     *  succeeds even while a separate process holds the SAME database
     *  open for writing (RocksDB's single-writer lock only applies to
     *  read-write handles; a genuinely separate, dedicated read-only
     *  mode exists specifically for exactly this: a diagnostic tool
     *  reading a live database's current state without needing to stop
     *  whatever's actively writing to it). Gives a consistent,
     *  point-in-time snapshot as of when it was opened -- later writes
     *  from the live process aren't visible without reopening, which is
     *  the correct, expected behavior for a diagnostic read, not a bug. */
    public RocksDBKVStore(String path, boolean readOnly) {
        this(path, readOnly, -1L);
    }

    /** blockCacheBytesOverride: -1 means "auto-detect from total system
     *  RAM" (detectSharedBlockCacheBytes() below) -- the right default
     *  for this project's one long-lived chain database, where a large
     *  cache pays for itself over the database's entire lifetime. Any
     *  non-negative value bypasses detection entirely and uses exactly
     *  that many bytes instead.
     *
     *  FIX: added specifically for DiskBackedHashKeySet, which opens a
     *  brand-new RocksDBKVStore for every single reconciliation walk
     *  (roughly every 360 blocks near the tip) purely as a throwaway,
     *  single-cycle dedup set -- confirmed, directly from this
     *  constructor's own pre-fix behavior, that each of those short-
     *  lived instances was sizing its block cache the same way the
     *  main chain database does: 10% of TOTAL SYSTEM RAM, up to a 4GB
     *  ceiling, entirely native (off-heap) memory invisible to the
     *  JVM's own -Xmx and to any heap-based monitoring. On a real run
     *  that repeated this several hundred times over a long sync, this
     *  was real, reported system memory pressure (a machine going
     *  unusable) that never showed up in the JVM heap numbers being
     *  watched, because it genuinely wasn't JVM heap. A small dedup set
     *  gets no real benefit from a multi-gigabyte block cache sized for
     *  a permanent database -- it just needs to survive one walk. */
    public RocksDBKVStore(String path, boolean readOnly, long blockCacheBytesOverride) {
        this(path, readOnly, blockCacheBytesOverride, false);
    }

    /** countAsScratch: this is a short-lived scratch store (orphan pruning); when it closes, the bytes it wrote and
     *  read are added to the totals reported by {@link #scratchIoStats()}, so that disk activity is not invisible. */
    public RocksDBKVStore(String path, boolean readOnly, long blockCacheBytesOverride, boolean countAsScratch) {
        this.countAsScratch = countAsScratch;
        if (!countAsScratch && !readOnly && blockCacheBytesOverride < 0)
            System.out.printf("[RocksDBKVStore] RAM %.1f GB -> memory tier %d: Urkel write buffer %d MB, names/UTXO buffer %d MB, block cache %d MB%n",
                    physicalMemoryBytes() / 1073741824.0, MEMORY_TIER, HIGH_VOLUME_WRITE_BUFFER_SIZE_BYTES >> 20,
                    CHURN_WRITE_BUFFER_SIZE_BYTES >> 20, detectSharedBlockCacheBytes() >> 20);
        RocksDB.loadLibrary();
        this.path = path;
        this.readOnly = readOnly;
        if (!readOnly) new File(path).mkdirs();
        this.sharedBlockCache = new LRUCache(
                blockCacheBytesOverride >= 0 ? blockCacheBytesOverride : detectSharedBlockCacheBytes());

        this.statistics = new Statistics();
        this.dbOptions = new DBOptions()
                .setCreateIfMissing(!readOnly)
                .setCreateMissingColumnFamilies(!readOnly)
                .setStatistics(statistics)
                .setListeners(List.of(compactionListener()))
                // Compaction reads whole files in 2MB sequential chunks instead of many small reads: far fewer disk operations
                .setCompactionReadaheadSize(2L * 1024 * 1024);
        // CRASH CONSISTENCY: with several column families sharing one write-ahead log, flushing one family's memtable
        // to disk while another's is still only in the log can leave the families at different points in time after a
        // power cut (e.g. names ahead of the block tip). Atomic flush makes RocksDB flush all families together, so the
        // recovered database is one consistent point in time. (Not needed for read-only or throwaway scratch stores.)
        if (!readOnly && !countAsScratch) dbOptions.setAtomicFlush(true);

        List<byte[]> existingNames;
        try {
            existingNames = RocksDB.listColumnFamilies(new Options().setCreateIfMissing(!readOnly), path);
        } catch (RocksDBException e) {
            existingNames = new ArrayList<>();
        }
        // A brand new database (nothing discovered above) still needs
        // "default" explicitly listed -- RocksDB.open()'s multi-column-
        // family overload requires it to always be present in the
        // descriptor list, even when nothing has ever been written to
        // it, confirmed directly against the real API before relying
        // on it here.
        if (existingNames.isEmpty()) {
            existingNames = List.of(RocksDB.DEFAULT_COLUMN_FAMILY);
        }

        List<ColumnFamilyDescriptor> descriptors = new ArrayList<>();
        for (byte[] name : existingNames) {
            ColumnFamilyOptions cfOptions = newBoundedCfOptions(new String(name, StandardCharsets.UTF_8));
            openedCfOptions.add(cfOptions);
            descriptors.add(new ColumnFamilyDescriptor(name, cfOptions));
        }

        List<ColumnFamilyHandle> handleList = new ArrayList<>();
        try {
            this.db = readOnly
                    ? RocksDB.openReadOnly(dbOptions, path, descriptors, handleList)
                    : RocksDB.open(dbOptions, path, descriptors, handleList);
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }

        for (int i = 0; i < existingNames.size(); i++) {
            handles.put(new String(existingNames.get(i), StandardCharsets.UTF_8), handleList.get(i));
        }
        this.batchCtx = new BatchContext(db);
    }

    // ── atomic write batch (see KVStore.beginBatch) ───────────────────────────

    @Override public void beginBatch()   { if (!readOnly) batchCtx.begin(); }
    @Override public void commitBatch()  { if (!readOnly) batchCtx.commit(); }
    @Override public void discardBatch() { if (!readOnly) batchCtx.discard(); }
    @Override public boolean batchOpen() { return batchCtx.active(); }

    /** Builds a ColumnFamilyOptions bounded to the constants above --
     *  every column family this store ever opens (both the initial
     *  discovery loop above and getOrCreateHandle() below) goes through
     *  this single place, so there's exactly one spot controlling the
     *  memory/performance tradeoff, not options scattered and
     *  potentially drifting out of sync across call sites. */
    /** Column families whose reads are mostly point lookups by key, many of them for keys that are not there yet
     *  (new Urkel nodes, new UTXOs, new names): a bloom filter answers "not in this file" from memory, so those
     *  lookups no longer read several files from disk. About 10 bits (1.25 bytes) per key, kept inside the block cache. */
    private static boolean wantsBloomFilter(String n) {
        return n.equals("urkelNodes") || n.equals("utxos") || n.equals("names") || n.equals("hashIndex");
    }

    private ColumnFamilyOptions newBoundedCfOptions(String cfName) {
        BlockBasedTableConfig tableConfig = new BlockBasedTableConfig()
                .setBlockCache(sharedBlockCache)
                // index and filter blocks live INSIDE the (bounded) block cache, so their memory is capped too
                .setCacheIndexAndFilterBlocks(true)
                .setPinL0FilterAndIndexBlocksInCache(true);
        if (wantsBloomFilter(cfName)) {
            BloomFilter bloom = new BloomFilter(10, false);
            filterPolicies.add(bloom);
            tableConfig.setFilterPolicy(bloom);
        }
        long writeBufferSize = HIGH_VOLUME_COLUMN_FAMILY.equals(cfName)
                ? HIGH_VOLUME_WRITE_BUFFER_SIZE_BYTES
                : isChurnFamily(cfName) ? CHURN_WRITE_BUFFER_SIZE_BYTES
                : isIndexFamily(cfName) ? INDEX_WRITE_BUFFER_SIZE_BYTES : DEFAULT_WRITE_BUFFER_SIZE_BYTES;
        boolean churn = MEMORY_TIER > 0 && (HIGH_VOLUME_COLUMN_FAMILY.equals(cfName) || isChurnFamily(cfName));
        ColumnFamilyOptions o = new ColumnFamilyOptions()
                .setTableFormatConfig(tableConfig)
                .setWriteBufferSize(writeBufferSize)
                .setMaxWriteBufferNumber(churn ? 3 : MAX_WRITE_BUFFER_NUMBER);
        if (churn) {
            // Merge two full memtables before writing one file, so an entry created in one and deleted in the other
            // never reaches disk; and let 8 level-0 files pile up before compacting (bloom filters keep reads cheap).
            o.setMinWriteBufferNumberToMerge(2).setLevel0FileNumCompactionTrigger(8);
        }
        // Urkel nodes are hashes: incompressible, so compressing them only burns CPU. Everything else uses fast LZ4.
        o.setCompressionType(HIGH_VOLUME_COLUMN_FAMILY.equals(cfName)
                ? CompressionType.NO_COMPRESSION : CompressionType.LZ4_COMPRESSION);
        return o;
    }

    // ── disk I/O counters ─────────────────────────────────────────────────────

    /** Records every finished compaction under its column family, so the log can say WHICH family causes the
     *  compaction traffic. Runs on RocksDB's background threads: kept tiny and never allowed to throw. */
    private AbstractEventListener compactionListener() {
        AbstractEventListener l = new AbstractEventListener(AbstractEventListener.EnabledEventCallback.ON_COMPACTION_COMPLETED) {
            @Override
            public void onCompactionCompleted(RocksDB d, CompactionJobInfo info) {
                try {
                    String cf = new String(info.columnFamilyName(), StandardCharsets.UTF_8);
                    CompactionJobStats st = info.stats();
                    long[] a = compactionByFamily.computeIfAbsent(cf, k -> new long[7]);
                    synchronized (a) {
                        a[0]++;
                        if (info.baseInputLevel() == 0) a[1]++;
                        a[2] += st.totalInputBytes();
                        a[3] += st.totalOutputBytes();
                        a[4] += st.numRecordsReplaced();
                        a[5] += st.numInputDeletionRecords();
                        a[6] += st.elapsedMicros();
                    }
                } catch (Throwable ignored) { /* statistics must never disturb the database */ }
            }
        };
        filterPolicies.add(l);          // closed together with the other native helpers
        return l;
    }

    /** "urkelNodes 12 jobs (4 from L0): read 3.4 GB, wrote 3.1 GB, 1.2M replaced, 0.4M deletes, 35 s | utxos ..." since the previous call. */
    private String compactionByFamilyText() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, long[]> e : new TreeMap<>(compactionByFamily).entrySet()) {
            long[] cur;
            synchronized (e.getValue()) { cur = e.getValue().clone(); }
            long[] prev = compactionReported.getOrDefault(e.getKey(), new long[7]);
            compactionReported.put(e.getKey(), cur);
            if (cur[0] == prev[0]) continue;
            if (sb.length() > 0) sb.append("; ");
            sb.append(String.format("%s %d jobs (%d from L0): read %s, wrote %s, %s replaced, %s deletes, %d s",
                    e.getKey(), cur[0] - prev[0], cur[1] - prev[1], mb(cur[2] - prev[2]), mb(cur[3] - prev[3]),
                    count(cur[4] - prev[4]), count(cur[5] - prev[5]), (cur[6] - prev[6]) / 1_000_000));
        }
        return sb.length() == 0 ? "none" : sb.toString();
    }

    private static String count(long n) { return n >= 1_000_000 ? String.format("%.1fM", n / 1e6) : n >= 1000 ? (n / 1000) + "k" : String.valueOf(n); }

    private static final java.util.concurrent.atomic.LongAdder SCRATCH_STORES = new java.util.concurrent.atomic.LongAdder();
    private static final java.util.concurrent.atomic.LongAdder SCRATCH_WRITTEN = new java.util.concurrent.atomic.LongAdder();
    private static final java.util.concurrent.atomic.LongAdder SCRATCH_READ = new java.util.concurrent.atomic.LongAdder();
    private static long lastScratchStores, lastScratchWritten, lastScratchRead;

    /** Disk activity of the short-lived scratch stores (orphan pruning) that finished since the previous call. */
    public static synchronized String scratchIoStats() {
        long n = SCRATCH_STORES.sum(), w = SCRATCH_WRITTEN.sum(), r = SCRATCH_READ.sum();
        String out = String.format("scratch stores: %d finished, wrote %s, compaction read %s", n - lastScratchStores,
                mb(w - lastScratchWritten), mb(r - lastScratchRead));
        lastScratchStores = n; lastScratchWritten = w; lastScratchRead = r;
        return out;
    }

    private long lastFlushW, lastCompR, lastCompW, lastWal, lastHit, lastMiss, lastBloom, lastNanos = System.nanoTime();

    /** Disk activity since the previous call, e.g. for a periodic log line. Bytes are what RocksDB itself wrote
     *  and read for flushes, compaction and the write-ahead log, plus how well the cache and bloom filters worked. */
    @Override
    public synchronized String ioStats() {
        long flushW = statistics.getTickerCount(TickerType.FLUSH_WRITE_BYTES);
        long compR = statistics.getTickerCount(TickerType.COMPACT_READ_BYTES);
        long compW = statistics.getTickerCount(TickerType.COMPACT_WRITE_BYTES);
        long wal = statistics.getTickerCount(TickerType.WAL_FILE_BYTES);
        long hit = statistics.getTickerCount(TickerType.BLOCK_CACHE_HIT);
        long miss = statistics.getTickerCount(TickerType.BLOCK_CACHE_MISS);
        long bloom = statistics.getTickerCount(TickerType.BLOOM_FILTER_USEFUL);
        long now = System.nanoTime();
        double secs = Math.max(0.001, (now - lastNanos) / 1e9);
        long dFlush = flushW - lastFlushW, dCompR = compR - lastCompR, dCompW = compW - lastCompW, dWal = wal - lastWal;
        long dHit = hit - lastHit, dMiss = miss - lastMiss, dBloom = bloom - lastBloom;
        lastFlushW = flushW; lastCompR = compR; lastCompW = compW; lastWal = wal; lastHit = hit; lastMiss = miss; lastBloom = bloom; lastNanos = now;
        long written = dFlush + dCompW + dWal;
        return String.format("disk write %s (%s/s: log %s, flush %s, compaction %s) | compaction read %s | cache hit %d%% | bloom skipped %d file reads | compaction by family: %s",
                mb(written), mb((long) (written / secs)), mb(dWal), mb(dFlush), mb(dCompW), mb(dCompR),
                dHit + dMiss == 0 ? 100 : (100 * dHit) / (dHit + dMiss), dBloom, compactionByFamilyText());
    }

    private static String mb(long bytes) { return String.format("%.1f MB", bytes / 1048576.0); }

    private synchronized ColumnFamilyHandle getOrCreateHandle(String name) {
        ColumnFamilyHandle existing = handles.get(name);
        if (existing != null) return existing;
        if (readOnly) {
            throw new IllegalStateException(
                    "Column family \"" + name + "\" doesn't exist, and this store was opened "
                            + "read-only -- a diagnostic tool should only ever open maps that already "
                            + "exist in the live database it's reading.");
        }
        try {
            ColumnFamilyOptions cfOptions = newBoundedCfOptions(name);
            openedCfOptions.add(cfOptions);
            ColumnFamilyHandle created = db.createColumnFamily(
                    new ColumnFamilyDescriptor(name.getBytes(StandardCharsets.UTF_8), cfOptions));
            handles.put(name, created);
            return created;
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
    }

    // ── Encoding helpers ─────────────────────────────────────────────────────
    // Long keys/values use a fixed 8-byte big-endian encoding -- plain,
    // unambiguous, and (though not currently required by anything here)
    // preserves correct numeric ordering under RocksDB's own default
    // byte-lexicographic key ordering, for free.

    private static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte) (v & 0xFF); v >>>= 8; }
        return b;
    }

    private static long bytesToLong(byte[] b) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[i] & 0xFF);
        return v;
    }

    private static final Function<byte[], byte[]> IDENTITY = b -> b;

    @Override
    public KVMap<Long, byte[]> openLongBytesMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                RocksDBKVStore::longToBytes, RocksDBKVStore::bytesToLong,
                IDENTITY, IDENTITY,
                batchCtx);
    }

    @Override
    public KVMap<String, String> openStringStringMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8),
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8),
                batchCtx);
    }

    @Override
    public KVMap<String, byte[]> openStringBytesMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8),
                IDENTITY, IDENTITY,
                batchCtx);
    }

    @Override
    public KVMap<String, Long> openStringLongMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8),
                RocksDBKVStore::longToBytes, RocksDBKVStore::bytesToLong,
                batchCtx);
    }

    /** RE-ARCHITECTURE: part of the project's byte-keyed-storage change
     *  -- see KVStore.openBytesBytesMap()'s own comment for why this
     *  exists. Mechanically identical to openStringBytesMap() above,
     *  just with IDENTITY in place of the UTF-8 string encode/decode
     *  pair on the key side -- RocksDBKVMap was already written generic
     *  over arbitrary key/value codecs, so a raw-byte key needs no new
     *  code in that class at all, only a different codec passed in
     *  here. */
    @Override
    public KVMap<byte[], byte[]> openBytesBytesMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                IDENTITY, IDENTITY,
                IDENTITY, IDENTITY,
                batchCtx);
    }

    /** Same reasoning as openBytesBytesMap() just above, for the one
     *  byte[]-keyed, Long-valued map this project needs (hashIndex:
     *  block hash -> height). */
    @Override
    public KVMap<byte[], Long> openBytesLongMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                IDENTITY, IDENTITY,
                RocksDBKVStore::longToBytes, RocksDBKVStore::bytesToLong,
                batchCtx);
    }

    /** Same reasoning as the two methods just above, for the byte[]-keyed,
     *  String-valued shape `names` and `utxos` need (see
     *  KVStore.openBytesStringMap()'s own comment for why those two
     *  specifically keep String values rather than moving to raw bytes). */
    @Override
    public KVMap<byte[], String> openBytesStringMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                IDENTITY, IDENTITY,
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8),
                batchCtx);
    }

    /** RocksDB durability is governed by WriteOptions/its own WAL
     *  settings on each individual write, not a separate, explicit
     *  "commit the current version" call the way MVStore needs --
     *  flushing the WAL here is the closest real equivalent to what
     *  every existing caller of commit() actually wants ("make sure
     *  this is safely durable"), without changing per-write behavior
     *  elsewhere. */
    @Override
    public void createCheckpoint(String dir) {
        try (org.rocksdb.Checkpoint cp = org.rocksdb.Checkpoint.create(db)) {
            cp.createCheckpoint(dir);
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void commit() {
        if (readOnly) return; // nothing to flush -- a read-only handle never writes anything
        try {
            db.flushWal(true);
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
    }

    /** A genuine no-op, not a stub -- RocksDB's own background
     *  compaction (a core part of its LSM-tree design) reclaims space
     *  from superseded data automatically, continuously, without
     *  needing an application-driven call the way MVStore's
     *  compactFile() did. There is no equivalent gap here to fill. */
    @Override
    public void compact(int maxMillis) {
        // Intentionally empty.
    }

    @Override
    public String getFileName() {
        return path;
    }

    @Override
    public long getDiskSizeBytes() {
        // RocksDB stores its data as a directory of multiple files,
        // not one single file the way MVStore does -- sums the whole
        // directory recursively rather than checking one file's length.
        return directorySize(new File(path));
    }

    private static long directorySize(File dir) {
        long total = 0;
        File[] files = dir.listFiles();
        if (files == null) return 0;
        for (File f : files) {
            total += f.isDirectory() ? directorySize(f) : f.length();
        }
        return total;
    }

    @Override
    public void close() {
        for (ColumnFamilyHandle h : handles.values()) h.close();
        db.close();
        dbOptions.close();
        for (ColumnFamilyOptions o : openedCfOptions) o.close();
        if (countAsScratch) {
            SCRATCH_STORES.increment();
            SCRATCH_WRITTEN.add(statistics.getTickerCount(TickerType.FLUSH_WRITE_BYTES)
                    + statistics.getTickerCount(TickerType.COMPACT_WRITE_BYTES) + statistics.getTickerCount(TickerType.WAL_FILE_BYTES));
            SCRATCH_READ.add(statistics.getTickerCount(TickerType.COMPACT_READ_BYTES));
        }
        for (AbstractNativeReference r : filterPolicies) r.close();
        statistics.close();
        sharedBlockCache.close(); // native resource -- must be released explicitly, same as everything else here
    }
}