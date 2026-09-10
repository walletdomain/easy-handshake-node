package handshake.node;

/**
 * The storage engine abstraction -- everything ChainDB and
 * UrkelNodeStore need from whatever's actually persisting the chain
 * database. Four typed openXxxMap() variants rather than one generic
 * openMap() because that's the exact set of key/value type
 * combinations this codebase actually uses (confirmed directly against
 * every existing MVMap<K,V> field declaration before designing this) --
 * preserving that type safety at the call site is what keeps this
 * refactor mechanical rather than a rewrite: a field declared
 * KVMap<Long, byte[]> instead of MVMap<Long, byte[]> needs no change
 * anywhere else in the method that uses it.
 */
public interface KVStore {
    KVMap<Long, byte[]> openLongBytesMap(String name);
    KVMap<String, String> openStringStringMap(String name);
    KVMap<String, byte[]> openStringBytesMap(String name);
    KVMap<String, Long> openStringLongMap(String name);

    /** Makes the current version durable. Engine-agnostic in name only
     *  right now -- this genuinely is an MVStore-specific concept
     *  (explicit, on-demand version commits), which a future RocksDB
     *  implementation would most likely make a no-op (RocksDB durability
     *  is governed by its own WAL/flush settings, not an explicit call
     *  like this) -- kept in the interface because every existing
     *  caller already calls it expecting "make sure this is safely on
     *  disk," which is the right level of abstraction to preserve even
     *  if what satisfies it differs by engine. */
    void commit();

    /** Reclaims disk space from old, superseded data -- time-bounded so
     *  a periodic caller can never be stalled for an unpredictable
     *  length of time. Also engine-specific in mechanism (MVStore's own
     *  chunk compaction vs. RocksDB's native background compaction,
     *  which typically wouldn't need an explicit call like this at
     *  all), same reasoning as commit(). */
    void compact(int maxMillis);

    String getFileName();
    long getDiskSizeBytes();
    void close();
}