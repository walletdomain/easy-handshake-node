package handshake.node;

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
 */
public class RocksDBKVStore implements KVStore {

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
    private static final long SHARED_BLOCK_CACHE_BYTES = 128L * 1024 * 1024;        // 128MB, shared across ALL column families
    private static final long DEFAULT_WRITE_BUFFER_SIZE_BYTES = 16L * 1024 * 1024;  // 16MB per memtable for low-write-volume column families
    private static final long HIGH_VOLUME_WRITE_BUFFER_SIZE_BYTES = 64L * 1024 * 1024; // 64MB for "urkelNodes" specifically -- close to RocksDB's own original default
    private static final String HIGH_VOLUME_COLUMN_FAMILY = "urkelNodes";
    private static final int MAX_WRITE_BUFFER_NUMBER = 2;                      // RocksDB's own default -- kept, not reduced further, since going lower would force more frequent flushes and hurt write throughput for little further memory benefit

    private final RocksDB db;
    private final DBOptions dbOptions;
    private final String path;
    private final boolean readOnly;
    private final Map<String, ColumnFamilyHandle> handles = new HashMap<>();
    private final List<ColumnFamilyOptions> openedCfOptions = new ArrayList<>();
    private final Cache sharedBlockCache;

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
        RocksDB.loadLibrary();
        this.path = path;
        this.readOnly = readOnly;
        if (!readOnly) new File(path).mkdirs();
        this.sharedBlockCache = new LRUCache(SHARED_BLOCK_CACHE_BYTES);

        this.dbOptions = new DBOptions()
                .setCreateIfMissing(!readOnly)
                .setCreateMissingColumnFamilies(!readOnly);

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
    }

    /** Builds a ColumnFamilyOptions bounded to the constants above --
     *  every column family this store ever opens (both the initial
     *  discovery loop above and getOrCreateHandle() below) goes through
     *  this single place, so there's exactly one spot controlling the
     *  memory/performance tradeoff, not options scattered and
     *  potentially drifting out of sync across call sites. */
    private ColumnFamilyOptions newBoundedCfOptions(String cfName) {
        BlockBasedTableConfig tableConfig = new BlockBasedTableConfig()
                .setBlockCache(sharedBlockCache);
        long writeBufferSize = HIGH_VOLUME_COLUMN_FAMILY.equals(cfName)
                ? HIGH_VOLUME_WRITE_BUFFER_SIZE_BYTES
                : DEFAULT_WRITE_BUFFER_SIZE_BYTES;
        return new ColumnFamilyOptions()
                .setTableFormatConfig(tableConfig)
                .setWriteBufferSize(writeBufferSize)
                .setMaxWriteBufferNumber(MAX_WRITE_BUFFER_NUMBER);
    }

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
                IDENTITY, IDENTITY);
    }

    @Override
    public KVMap<String, String> openStringStringMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8),
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8));
    }

    @Override
    public KVMap<String, byte[]> openStringBytesMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8),
                IDENTITY, IDENTITY);
    }

    @Override
    public KVMap<String, Long> openStringLongMap(String name) {
        ColumnFamilyHandle cf = getOrCreateHandle(name);
        return new RocksDBKVMap<>(db, cf,
                s -> s.getBytes(StandardCharsets.UTF_8), b -> new String(b, StandardCharsets.UTF_8),
                RocksDBKVStore::longToBytes, RocksDBKVStore::bytesToLong);
    }

    /** RocksDB durability is governed by WriteOptions/its own WAL
     *  settings on each individual write, not a separate, explicit
     *  "commit the current version" call the way MVStore needs --
     *  flushing the WAL here is the closest real equivalent to what
     *  every existing caller of commit() actually wants ("make sure
     *  this is safely durable"), without changing per-write behavior
     *  elsewhere. */
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
        sharedBlockCache.close(); // native resource -- must be released explicitly, same as everything else here
    }
}