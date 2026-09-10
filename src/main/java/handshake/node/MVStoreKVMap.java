package handshake.node;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;

/**
 * KVMap backed directly by an MVMap -- every method here is a pure,
 * direct delegation to the exact same MVMap call the code it replaces
 * used to make, so this refactor changes nothing about actual behavior,
 * only which class the behavior lives in.
 */
public class MVStoreKVMap<K, V> implements KVMap<K, V> {

    private final MVMap<K, V> map;
    private final MVStore mvStore;
    private final java.util.concurrent.locks.ReentrantLock maintenanceLock;

    /** mvStore is the map's own parent store -- needed here (not just
     *  in MVStoreKVStore) specifically for removeAll(), which has to
     *  manipulate the store's global autoCommitDelay setting.
     *
     *  maintenanceLock is shared across every map opened from the same
     *  MVStoreKVStore (the same object instance is passed to each) --
     *  see runExclusiveOfCompaction()'s own comment for why a single,
     *  store-wide lock is what's actually needed here, not a per-map
     *  one. */
    public MVStoreKVMap(MVMap<K, V> map, MVStore mvStore,
                        java.util.concurrent.locks.ReentrantLock maintenanceLock) {
        this.map = map;
        this.mvStore = mvStore;
        this.maintenanceLock = maintenanceLock;
    }

    @Override public V get(K key) { return map.get(key); }
    @Override public V put(K key, V value) { return map.put(key, value); }
    @Override public V remove(K key) { return map.remove(key); }
    @Override public boolean containsKey(K key) { return map.containsKey(key); }
    @Override public int size() { return map.size(); }
    @Override public void clear() { map.clear(); }
    @Override public Iterable<V> values() { return map.values(); }
    @Override public Iterable<java.util.Map.Entry<K, V>> entrySet() { return map.entrySet(); }
    @Override public java.util.Set<K> keySet() { return map.keySet(); }
    @Override public java.util.Map<K, V> asUnmodifiableMap() {
        return java.util.Collections.unmodifiableMap(map);
    }

    /** No dramatic batching win here the way RocksDBKVMap's WriteBatch
     *  gives -- MVMap's own put() is already a direct, in-memory
     *  B-tree operation, not something with a separate network/JNI
     *  round-trip per call to amortize away. A plain loop, for
     *  interface completeness -- kept correct and simple rather than
     *  reaching for MVStore-specific batching machinery for an engine
     *  that's no longer the active production path. */
    @Override
    public void putAll(java.util.Map<K, V> entries) {
        for (java.util.Map.Entry<K, V> e : entries.entrySet()) {
            map.put(e.getKey(), e.getValue());
        }
    }

    /** FIX: previously only the removal phase of a prune was
     *  synchronized against MVStoreKVStore's own compact() -- but a
     *  real, repeatedly observed "Chunk ... not found" error kept
     *  recurring even after raising MVStore's retention time well
     *  beyond any observed walk duration, which ruled out "the walk
     *  simply outlasted the retention window" as the (sole) cause.
     *  compactFile() doesn't just reclaim old, dead versions after
     *  retention expires -- it actively DEFRAGMENTS the file,
     *  physically moving and renumbering live chunks, which can
     *  invalidate a chunk reference the walk is mid-read on regardless
     *  of retention timing. The walk itself was never protected
     *  against this at all before now.
     *
     *  Held for the WHOLE prune (walk + removal together), acquired
     *  with a normal blocking lock() here -- safe because this always
     *  runs on its own dedicated background thread, which has nothing
     *  else to do but wait if compact() happens to be mid-cycle.
     *  compact() itself uses tryLock() (see MVStoreKVStore), never
     *  this blocking acquire, specifically so it can never stall the
     *  MAIN sync thread waiting on a lock a background prune might
     *  hold for a minute or more -- that would silently reintroduce
     *  the exact main-thread-blocking problem the background-threaded
     *  prune was built to eliminate in the first place. */
    @Override
    public <T> T runExclusiveOfCompaction(java.util.function.Supplier<T> operation) {
        maintenanceLock.lock();
        try {
            return operation.get();
        } finally {
            maintenanceLock.unlock();
        }
    }

    /** FIX (carried forward unchanged from before this refactor):
     *  previously each of potentially hundreds of thousands of
     *  individual remove() calls could be interrupted by MVStore's own
     *  automatic background writer (confirmed to run independently,
     *  roughly once a second, per H2's own MVStore docs), forcing a
     *  real disk write plus re-compression for whatever had
     *  accumulated so far, rather than one single flush at the end.
     *  Confirmed as a major, real cost via direct timing
     *  instrumentation: bulk removals of 50,000-200,000 entries were
     *  taking 66-97 SECONDS (roughly 1-2ms per removal, far slower
     *  than a simple in-memory B-tree deletion should be) before this
     *  fix. Disabling auto-commit for the duration of the removal loop,
     *  then committing exactly once at the end, means the whole batch
     *  gets written as a single, efficient operation instead of dozens
     *  of small, interrupted ones.
     *
     *  No longer separately synchronized here -- this is only ever
     *  called from inside runExclusiveOfCompaction() now (see
     *  UrkelTree.pruneUnreachableFrom()), which already holds the same
     *  lock for the whole walk-then-remove operation. */
    @Override
    public int removeAll(java.util.Collection<K> keys) {
        int previousDelay = mvStore.getAutoCommitDelay();
        try {
            mvStore.setAutoCommitDelay(0); // 0 disables the periodic background commit
            for (K key : keys) {
                map.remove(key);
            }
            mvStore.commit();
        } finally {
            mvStore.setAutoCommitDelay(previousDelay);
        }
        // Matches the exact behavior this replaces: the count of
        // keys attempted, not a re-verified "actually existed and
        // was removed" count -- every key here is already known to
        // have existed at snapshot time by construction (see
        // UrkelNodeStore.pruneUnreachable()'s own reasoning).
        return keys.size();
    }
}