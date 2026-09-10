package handshake.node;

import org.h2.mvstore.MVStore;

import java.io.File;

/**
 * KVStore backed directly by MVStore -- the current, only production
 * implementation. Every method is a direct delegation to the exact
 * same MVStore call the code it replaces used to make.
 */
public class MVStoreKVStore implements KVStore {

    private final MVStore store;

    /** Shared across every map opened from this store -- see
     *  MVStoreKVMap.runExclusiveOfCompaction()'s own comment for why a
     *  single, store-wide lock (not a per-map one) is what's actually
     *  needed: compact() operates on the whole file, not one map, so
     *  it needs to be excluded from ANY map's long-running exclusive
     *  operation, not just the one it happens to be called on. */
    private final java.util.concurrent.locks.ReentrantLock maintenanceLock =
            new java.util.concurrent.locks.ReentrantLock();

    public MVStoreKVStore(String path) {
        new File(path).getParentFile().mkdirs();
        this.store = new MVStore.Builder()
                .fileName(path)
                .compress()
                // FIX (carried forward unchanged from before this
                // refactor): H2's own default read cache is only 16MB
                // -- confirmed directly from H2's own source/javadoc.
                // With a tree holding well over a million names,
                // that's nowhere near enough to keep any meaningful
                // fraction of it resident: nearly every single node
                // resolution during a prune's reachability walk (or a
                // "cold" name lookup after a restart) misses this tiny
                // cache and goes straight to disk. Confirmed as the
                // direct match for a real, observed sustained disk I/O
                // spike (up to 80% in Windows Task Manager) during
                // exactly the operations already identified as the
                // processing bottleneck.
                //
                // 1024MB is a deliberately conservative choice, not the
                // largest safe value -- this cache is a regular on-heap
                // object, not off-heap, so it competes with the live
                // in-memory tree, the UTXO working set, and everything
                // else for the same -Xmx budget. A real GC log from
                // this exact codebase already showed live (post-
                // collection) heap usage climbing past 900MB during
                // header sync alone, before real block processing's
                // own tree/UTXO growth is even factored in -- stacking
                // a much larger cache on top of an 8GB heap risked
                // reintroducing the same GC pressure problem the heap
                // size increase was meant to solve in the first place.
                // 1024MB is still a 64x improvement over the default
                // while leaving substantial room for everything else.
                .cacheSize(1024)
                .open();
        // FIX: raised well beyond H2's own default (45 seconds) --
        // confirmed directly against H2's own bug tracker (issue #2118)
        // and its own javadoc as the exact, known cause of a real,
        // repeatedly observed "Chunk ... not found" error: "the
        // retention time needs to be long enough to allow reading old
        // chunks while traversing over the entries of a map." That's
        // precisely what the background prune's walk does -- a single,
        // long-running traversal over urkelNodes -- and it regularly
        // takes 60-95+ seconds, LONGER than the 45-second default this
        // setting exists to protect against. Every time that happened,
        // a chunk the walk still needed to read could be reclaimed by
        // the main thread's own concurrent writes before the walk
        // finished with it. 300 seconds gives real margin above the
        // longest walk duration observed so far. This is the opposite
        // of the earlier, dangerous retentionTime(0) experiment (see
        // the comment just below): that gave zero safety margin at
        // all; this gives deliberately more than the walk should ever
        // need, which is exactly what H2's own documentation
        // recommends for a long-running traversal like this one.
        store.setRetentionTime(300_000);
        // MVStore is versioned/copy-on-write: overwriting or clearing a
        // key doesn't erase the old bytes in place, it writes a new
        // chunk and leaves the old one on disk until compaction reclaims
        // it. This project used to force retentionTime(0) here to
        // reclaim that space more aggressively (see compact() below,
        // which still does the real work of reclaiming it) -- but
        // retentionTime(0) turned out to be a real, documented H2 risk,
        // not just a performance tradeoff: with retention at 0, H2 can
        // reuse a chunk's blocks while the chunk map written at close
        // still references that chunk, which can leave the file
        // requiring a very slow (or effectively stuck) recovery scan on
        // the next open, or refusing to open at all -- confirmed
        // directly against H2's own issue tracker, and consistent with
        // a real hang observed here after an unclean shutdown. Left at
        // H2's own default (45 seconds) now; periodic compact() calls
        // still reclaim the same disk space this was originally added
        // for, just without that risk.
    }

    @Override
    public KVMap<Long, byte[]> openLongBytesMap(String name) {
        return new MVStoreKVMap<>(store.openMap(name), store, maintenanceLock);
    }

    @Override
    public KVMap<String, String> openStringStringMap(String name) {
        return new MVStoreKVMap<>(store.openMap(name), store, maintenanceLock);
    }

    @Override
    public KVMap<String, byte[]> openStringBytesMap(String name) {
        return new MVStoreKVMap<>(store.openMap(name), store, maintenanceLock);
    }

    @Override
    public KVMap<String, Long> openStringLongMap(String name) {
        return new MVStoreKVMap<>(store.openMap(name), store, maintenanceLock);
    }

    @Override
    public void commit() {
        store.commit();
    }

    /** Reclaims disk space from old, no-longer-reachable chunks --
     *  MVStore's own commit() only makes the current version durable,
     *  it doesn't reclaim space from versions that are no longer
     *  needed (that's compaction's job specifically). Time-bounded
     *  rather than a single unbounded pass, so a periodic caller can
     *  never be stalled for an unpredictable length of time from
     *  compactFile() itself.
     *
     *  FIX: uses tryLock(), never a blocking acquire -- deliberately
     *  so this can NEVER stall the calling thread waiting for a
     *  background prune's exclusive walk-then-remove operation, which
     *  can legitimately hold this same lock for a minute or more (see
     *  MVStoreKVMap.runExclusiveOfCompaction()'s own comment for the
     *  full reasoning on why compaction and a prune's walk need to be
     *  mutually exclusive at all). If the lock isn't immediately
     *  available, this cycle's compaction is simply skipped -- safe to
     *  skip, since it's already just one of many periodic calls and
     *  the next one will try again shortly. */
    @Override
    public void compact(int maxMillis) {
        if (!maintenanceLock.tryLock()) {
            return; // a prune is holding this -- skip this cycle, try again next time
        }
        try {
            store.compactFile(maxMillis);
        } finally {
            maintenanceLock.unlock();
        }
    }

    @Override
    public String getFileName() {
        return store.getFileStore().getFileName();
    }

    @Override
    public long getDiskSizeBytes() {
        return new File(store.getFileStore().getFileName()).length();
    }

    @Override
    public void close() {
        store.close();
    }
}