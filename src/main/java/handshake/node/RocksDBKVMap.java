package handshake.node;

import org.rocksdb.*;

import java.util.*;
import java.util.function.Function;

/**
 * KVMap backed by a single RocksDB column family -- RocksDB's own
 * equivalent of MVStore's separate named maps. Generic over K/V using
 * explicit encoder/decoder functions (rather than four separate
 * classes) since RocksDB itself only ever deals in raw byte[] keys and
 * values; every type-specific concern lives entirely in these
 * functions, supplied once by RocksDBKVStore when each map is opened.
 */
public class RocksDBKVMap<K, V> implements KVMap<K, V> {

    private final RocksDB db;
    private final ColumnFamilyHandle cf;
    private final Function<K, byte[]> encodeKey;
    private final Function<byte[], K> decodeKey;
    private final Function<V, byte[]> encodeValue;
    private final Function<byte[], V> decodeValue;

    public RocksDBKVMap(RocksDB db, ColumnFamilyHandle cf,
                        Function<K, byte[]> encodeKey, Function<byte[], K> decodeKey,
                        Function<V, byte[]> encodeValue, Function<byte[], V> decodeValue) {
        this.db = db;
        this.cf = cf;
        this.encodeKey = encodeKey;
        this.decodeKey = decodeKey;
        this.encodeValue = encodeValue;
        this.decodeValue = decodeValue;
    }

    @Override
    public V get(K key) {
        try {
            byte[] raw = db.get(cf, encodeKey.apply(key));
            return raw == null ? null : decodeValue.apply(raw);
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public V put(K key, V value) {
        // Deliberately does NOT compute and return the previous value
        // the way MVMap's put() does -- confirmed directly, by
        // checking every real put() call site in this codebase, that
        // nothing anywhere actually uses that return value. Doing so
        // would require an extra get() before every single write,
        // purely to compute something never read -- a real,
        // unnecessary cost on what's actually a hot path (every
        // covenant-touching transaction writes here).
        try {
            db.put(cf, encodeKey.apply(key), encodeValue.apply(value));
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public V remove(K key) {
        // Same reasoning as put() -- confirmed nothing uses this
        // return value anywhere in this codebase, so this avoids an
        // unnecessary extra get() before every delete.
        try {
            db.delete(cf, encodeKey.apply(key));
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @Override
    public boolean containsKey(K key) {
        try {
            // RocksDB has no direct containsKey -- keyMayExist() is a
            // fast, possibly-false-positive bloom-filter check, so a
            // real get() is still needed to confirm; get() alone,
            // without the keyMayExist() pre-check, is simpler and
            // still correct, just not maximally fast for the
            // definitely-absent case. Not a hot enough path here to
            // warrant the extra complexity.
            return db.get(cf, encodeKey.apply(key)) != null;
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int size() {
        // RocksDB has no O(1) exact count (unlike MVMap's own B-tree,
        // which tracks this incrementally) -- getLongProperty's
        // "estimate-num-keys" is O(1) but explicitly approximate,
        // which isn't safe everywhere this is used (e.g.
        // backfillHashIndexIfNeeded()'s "size() >= tip + 1" comparison
        // needs to be exact, or it could incorrectly skip real,
        // needed backfill work). A full iteration is the only exact
        // option; only called for infrequent statistics/one-time
        // checks, never on a hot path.
        int count = 0;
        try (RocksIterator it = db.newIterator(cf)) {
            for (it.seekToFirst(); it.isValid(); it.next()) count++;
        }
        return count;
    }

    @Override
    public int sizeEstimate() {
        // RocksDB's own O(1) approximate property -- explicitly not
        // exact (per RocksDB's own docs, can drift from the true count,
        // especially soon after writes/compaction), which is exactly
        // why size() itself can't just use this everywhere -- but for
        // a purely informational count, this is the right tradeoff:
        // instant instead of a real, multi-minute full iteration at
        // real production scale.
        try {
            return (int) db.getLongProperty(cf, "rocksdb.estimate-num-keys");
        } catch (org.rocksdb.RocksDBException e) {
            // Fall back to the real, exact (but slow) count rather than
            // silently reporting 0 -- this should be rare (the property
            // itself is well-supported), but a startup banner showing
            // "0" for everything would be actively misleading.
            return size();
        }
    }

    @Override
    public void clear() {
        // No direct "clear this column family" call -- iterate and
        // delete via a WriteBatch rather than one delete() per key,
        // for the same reason removeAll() does (see its own comment).
        // Only called by fullReset(), an already-expensive, rare,
        // explicit user operation, so this doesn't need to be
        // hyper-optimized.
        List<byte[]> keys = new ArrayList<>();
        try (RocksIterator it = db.newIterator(cf)) {
            for (it.seekToFirst(); it.isValid(); it.next()) keys.add(it.key());
        }
        try (WriteBatch batch = new WriteBatch(); WriteOptions wOpts = new WriteOptions()) {
            for (byte[] k : keys) batch.delete(cf, k);
            db.write(wOpts, batch);
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Iterable<V> values() {
        // Eagerly materialized -- see entrySet()'s own comment for why
        // this is the safe choice, not just a simpler one.
        List<V> result = new ArrayList<>();
        try (RocksIterator it = db.newIterator(cf)) {
            for (it.seekToFirst(); it.isValid(); it.next()) {
                result.add(decodeValue.apply(it.value()));
            }
        }
        return result;
    }

    @Override
    public Iterable<Map.Entry<K, V>> entrySet() {
        // Eagerly materialized rather than a lazy iterator wrapping a
        // RocksIterator -- confirmed as a real, not theoretical,
        // concern: at least one actual caller in this codebase
        // (getNameByString()) returns from inside a for-each loop over
        // this exact result the moment it finds a match, which would
        // leak the RocksIterator's native resource on every single
        // call if iteration weren't guaranteed to run to completion.
        // Every real caller here is already documented as an
        // acceptable, infrequent linear scan (not a hot path), so
        // there's no real cost to eagerly loading the whole thing
        // inside one try-with-resources block instead.
        List<Map.Entry<K, V>> result = new ArrayList<>();
        try (RocksIterator it = db.newIterator(cf)) {
            for (it.seekToFirst(); it.isValid(); it.next()) {
                result.add(Map.entry(decodeKey.apply(it.key()), decodeValue.apply(it.value())));
            }
        }
        return result;
    }

    @Override
    public Set<K> keySet() {
        // Eagerly materialized, matching what every actual caller of
        // keySet() in this codebase already does with it (either
        // wraps it in `new HashSet<>(...)` immediately -- see
        // UrkelNodeStore.snapshotKeys() -- or iterates it once and
        // discards it), so there's no real behavioral difference, and
        // it keeps this method's return type a plain, safe Set rather
        // than a lazy view backed by an iterator that would need
        // explicit closing.
        Set<K> result = new LinkedHashSet<>();
        try (RocksIterator it = db.newIterator(cf)) {
            for (it.seekToFirst(); it.isValid(); it.next()) {
                result.add(decodeKey.apply(it.key()));
            }
        }
        return result;
    }

    @Override
    public Map<K, V> asUnmodifiableMap() {
        Map<K, V> result = new LinkedHashMap<>();
        try (RocksIterator it = db.newIterator(cf)) {
            for (it.seekToFirst(); it.isValid(); it.next()) {
                result.put(decodeKey.apply(it.key()), decodeValue.apply(it.value()));
            }
        }
        return Collections.unmodifiableMap(result);
    }

    /** No locking needed here, unlike MVStoreKVMap's own version of
     *  this method -- confirmed directly, empirically (not just by
     *  architectural reasoning) that RocksDB's snapshot isolation
     *  means a reader never needs to coordinate with concurrent
     *  writes or background compaction at all: an LSM-tree's
     *  compaction merges old SSTables into new ones, but never
     *  physically reorganizes a file a live reader still references
     *  the way MVStore's compactFile() does -- RocksDB's own internal
     *  reference counting keeps any SSTable a reader is actively
     *  using alive until that reader is done with it, automatically,
     *  with no application-level coordination required. This is the
     *  actual, structural fix for the real, repeatedly observed
     *  "Chunk ... not found" error under MVStore, not a workaround. */
    @Override
    public <T> T runExclusiveOfCompaction(java.util.function.Supplier<T> operation) {
        return operation.get();
    }

    /** Batches many writes into a single WriteBatch -- the write-path
     *  counterpart to removeAll() below, same reasoning: many
     *  individual put() calls each cross the JNI boundary and take an
     *  internal RocksDB lock separately; one batched write covering
     *  all of them does the whole thing as effectively one operation
     *  instead of many. Built specifically to address a real, measured
     *  cost: persistBlock() (writing newly-created Urkel tree nodes
     *  once per block) became the dominant per-block processing cost
     *  in real, high-covenant-volume ranges of the chain. */
    @Override
    public void putAll(Map<K, V> entries) {
        try (WriteBatch batch = new WriteBatch(); WriteOptions wOpts = new WriteOptions()) {
            for (Map.Entry<K, V> e : entries.entrySet()) {
                batch.put(cf, encodeKey.apply(e.getKey()), encodeValue.apply(e.getValue()));
            }
            db.write(wOpts, batch);
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
    }

    /** FIX (same reasoning as MVStoreKVMap.removeAll(), different
     *  mechanism): a WriteBatch groups many deletes into a single
     *  atomic, efficient write rather than one call per key -- this
     *  is RocksDB's own, native equivalent of the auto-commit-
     *  disabling trick MVStore needed, confirmed directly via a real
     *  compile-and-run test against the actual RocksDB API before
     *  ever being used here. */
    @Override
    public int removeAll(Collection<K> keys) {
        try (WriteBatch batch = new WriteBatch(); WriteOptions wOpts = new WriteOptions()) {
            for (K key : keys) {
                batch.delete(cf, encodeKey.apply(key));
            }
            db.write(wOpts, batch);
        } catch (RocksDBException e) {
            throw new RuntimeException(e);
        }
        // Matches the exact behavior this replaces: the count of keys
        // attempted, not a re-verified "actually existed" count.
        return keys.size();
    }

    /** Real, native RocksDB snapshot -- db.getSnapshot() is O(1),
     *  confirmed directly (via a real compile-and-run test against the
     *  actual RocksDB API) not to require copying or iterating
     *  anything upfront. The expensive part (actually enumerating
     *  keys) is deferred entirely into keys(), which callers are
     *  expected to invoke later, off the calling thread -- see
     *  KVMap.openSnapshot()'s own comment for why this specific split
     *  exists. */
    @Override
    public KVSnapshot<K> openSnapshot() {
        Snapshot snap = db.getSnapshot();
        return new KVSnapshot<K>() {
            @Override
            public Set<K> keys() {
                Set<K> result = new LinkedHashSet<>();
                try (ReadOptions readOpts = new ReadOptions().setSnapshot(snap);
                     RocksIterator it = db.newIterator(cf, readOpts)) {
                    for (it.seekToFirst(); it.isValid(); it.next()) {
                        result.add(decodeKey.apply(it.key()));
                    }
                }
                return result;
            }

            @Override
            public void forEachKey(java.util.function.Consumer<K> action) {
                // FIX: real, streaming iteration -- never materializes
                // more than one key at a time, unlike keys() above. See
                // KVSnapshot.forEachKey()'s own comment for the full
                // reasoning; this is the actual fix for a real,
                // confirmed OOM crash.
                try (ReadOptions readOpts = new ReadOptions().setSnapshot(snap);
                     RocksIterator it = db.newIterator(cf, readOpts)) {
                    for (it.seekToFirst(); it.isValid(); it.next()) {
                        action.accept(decodeKey.apply(it.key()));
                    }
                }
            }

            @Override
            public void close() {
                db.releaseSnapshot(snap);
                snap.close();
            }
        };
    }
}