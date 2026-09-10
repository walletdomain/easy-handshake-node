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
}