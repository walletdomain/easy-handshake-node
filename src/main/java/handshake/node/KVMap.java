package handshake.node;

/**
 * A single, named key-value collection within a KVStore -- the storage
 * abstraction ChainDB and UrkelNodeStore are built on, so that swapping
 * the underlying engine (e.g. to RocksDB) means writing one new
 * implementation of this interface, not touching either of those
 * classes' own logic.
 *
 * Deliberately narrow rather than mirroring java.util.Map's full
 * surface: this interface has exactly the methods actually used
 * anywhere in this codebase (confirmed directly by grepping every
 * .get()/.put()/.remove()/.containsKey()/.size()/.clear()/.values()/
 * .entrySet()/.keySet() call site before designing this), so a future
 * RocksDB-backed implementation never has to stub out methods nothing
 * here calls.
 */
public interface KVMap<K, V> {
    V get(K key);

    /** The return value is deliberately unspecified/implementation-
     *  defined -- unlike java.util.Map's own put(), which always
     *  returns the previous value. MVStoreKVMap happens to return the
     *  real previous value (free, since MVMap already computes it
     *  internally); RocksDBKVMap always returns null (computing it
     *  would need an extra read before every write, for something
     *  confirmed unused by every real caller in this codebase). Don't
     *  rely on this return value for anything -- if a future caller
     *  genuinely needs "was there a previous value," call get() first,
     *  explicitly. */
    V put(K key, V value);

    /** Same caveat as put() -- see its own comment. */
    V remove(K key);
    boolean containsKey(K key);
    int size();

    /** A fast, APPROXIMATE count -- for a backend like RocksDB with no
     *  O(1) exact count, size() itself does a real, full iteration (see
     *  RocksDBKVMap's own comment on size()), which is fine for the
     *  rare cases that genuinely need precision but was, confirmed
     *  directly, causing multi-minute silent startup stalls once this
     *  project's real databases reached millions of rows -- for a
     *  purely informational count (a startup banner, a progress
     *  estimate), exactness was never actually needed. Default
     *  implementation just delegates to size(): safe for a backend
     *  (MVStore) where that's already O(1), so only backends that
     *  actually need a faster, approximate path have to override this. */
    default int sizeEstimate() {
        return size();
    }

    void clear();
    Iterable<V> values();
    Iterable<java.util.Map.Entry<K, V>> entrySet();
    java.util.Set<K> keySet();

    /** A read-only view of the whole map -- used only where a caller
     *  genuinely needs to hand back "everything in this map" as a
     *  java.util.Map (e.g. an RPC method listing all known peers), not
     *  as a way to bypass the rest of this interface. */
    java.util.Map<K, V> asUnmodifiableMap();

    /** Runs a long-running operation (specifically: a prune's full
     *  walk-then-remove) with exclusive access relative to this
     *  store's own compact() -- see MVStoreKVStore's own comment for
     *  the full reasoning on why the WALK specifically (not just the
     *  removal) needs this protection. */
    <T> T runExclusiveOfCompaction(java.util.function.Supplier<T> operation);

    /**
     * Writes many key/value pairs as a single, coordinated operation --
     * the write-path counterpart to removeAll(), same reasoning: lets
     * the underlying storage engine batch this efficiently internally
     * (a RocksDB-backed implementation using its own native WriteBatch)
     * rather than one round-trip per entry.
     */
    void putAll(java.util.Map<K, V> entries);

    /**
     * Removes many keys as a single, coordinated operation -- lets the
     * underlying storage engine decide how to batch this efficiently
     * internally (e.g. an MVStore-backed implementation disabling
     * auto-commit for the duration; a RocksDB-backed one using its own
     * native WriteBatch) rather than exposing engine-specific
     * mechanics like "auto-commit" through this interface at all,
     * since that concept doesn't even exist for every possible engine.
     * Returns the number of keys actually removed.
     */
    int removeAll(java.util.Collection<K> keys);

    /**
     * Opens a lightweight, point-in-time snapshot of this map's current
     * key set -- for engines with real native snapshot support
     * (RocksDB), opening one is O(1) and does NOT require iterating or
     * copying anything upfront: the actual key enumeration (via
     * keys(), on the returned handle) can safely happen much LATER,
     * even after further writes to this map, and will still correctly
     * see exactly this moment's state, nothing added after.
     *
     * FIX: added specifically because a caller (UrkelNameTree.
     * maybeCommit(), via UrkelTree/UrkelNodeStore) previously had to
     * eagerly materialize the full key set synchronously, on the
     * caller's own thread, to get this same point-in-time guarantee --
     * correct, but a real, severe performance regression once the
     * store reached several million keys: a full iteration taking
     * 40+ seconds, blocking ALL block processing, every single commit.
     * This lets that same caller capture the O(1) snapshot HANDLE
     * synchronously (fast), while deferring the actual expensive
     * enumeration to a background thread -- getting the same
     * correctness guarantee without blocking anything.
     *
     * Callers MUST close() the returned KVSnapshot when done with it,
     * or the underlying engine keeps pinning whatever data existed at
     * snapshot time, unable to reclaim it -- a real, growing resource
     * leak, not just a style concern.
     */
    KVSnapshot<K> openSnapshot();

    /** A point-in-time view of a KVMap's key set, from openSnapshot().
     *  keys() may be called at any point after opening, including much
     *  later and even after further writes to the live map -- it will
     *  always reflect exactly the moment openSnapshot() was called. */
    interface KVSnapshot<K> extends AutoCloseable {
        java.util.Set<K> keys();

        /** Streams every key in this snapshot to action, one at a time,
         *  rather than materializing all of them into a Set first. Added
         *  specifically because keys() -- eagerly building a full,
         *  in-memory Set of every key in a column family -- was
         *  confirmed as a real, severe OutOfMemoryError cause at real
         *  production scale: tens of millions of entries (live names
         *  plus however much unpruned garbage has accumulated) all
         *  forced into memory at once, in one uninterrupted loop, was
         *  enough to jump heap usage by over a gigabyte within seconds
         *  -- fast enough that none of this project's other prune-
         *  related safeguards (periodic yielding, progress logging) ever
         *  got a chance to run, since all of those live in the walk
         *  phase that only starts AFTER this step. Default implementation
         *  just delegates to keys(): safe for a backend where that's
         *  already cheap, so only a backend that actually needs a
         *  genuinely streaming path has to override this. */
        default void forEachKey(java.util.function.Consumer<K> action) {
            for (K k : keys()) action.accept(k);
        }

        @Override void close();
    }
}