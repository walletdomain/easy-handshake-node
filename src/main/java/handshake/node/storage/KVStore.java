package handshake.node.storage;

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

    /** RE-ARCHITECTURE: added for the project's byte-keyed-storage
     *  change -- hash-keyed data (Urkel tree nodes, the block-hash
     *  index, name records) was previously stored under 64-character
     *  hex-string keys, doubling the real key size on disk and in the
     *  block cache versus the 32 raw bytes the hash actually needs.
     *  Added alongside the existing typed variants above, not a
     *  replacement for any of them -- `headers`/`blocks`/`chainwork`
     *  stay long-keyed, and small, low-volume maps (`meta`, `peers`,
     *  ConfigDB's settings/seeds/peerScores) stay string-keyed, since
     *  there's no real benefit there and `meta` specifically needs to
     *  stay a string map for its own human-readable settings.
     *
     *  A byte[] key needs no special handling at this interface
     *  boundary -- RocksDB's own native key comparator already does
     *  correct raw-byte comparison. The thing to watch is Java-side: a
     *  bare byte[] used as a *Java* collection key has identity-based
     *  equals()/hashCode(), not content-based, so any in-memory
     *  Set/Map built from these keys (not just storage reads/writes
     *  through this interface) must go through a wrapper with real
     *  content equality -- this project already has one,
     *  UrkelNodeStore.HashKey -- rather than a bare byte[].
     *
     *  Three byte[]-keyed variants, not one, for the same reason there
     *  were already four String/Long-keyed ones: `names` and `utxos`
     *  store genuinely text-shaped values (NameEntry/UtxoEntry's own
     *  pipe-delimited toStorage() encoding, confirmed directly against
     *  both classes), not raw bytes, so they need the byte[]-keyed,
     *  String-valued variant specifically -- `openBytesBytesMap` would
     *  be the wrong shape for them. */
    KVMap<byte[], byte[]> openBytesBytesMap(String name);
    KVMap<byte[], Long> openBytesLongMap(String name);
    KVMap<byte[], String> openBytesStringMap(String name);

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