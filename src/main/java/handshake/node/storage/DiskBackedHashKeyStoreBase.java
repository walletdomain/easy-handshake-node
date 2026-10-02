package handshake.node.storage;

// RE-ARCHITECTURE: added when this class moved into its own storage
// subpackage -- UrkelNodeStore.HashKey and HexUtil were previously
// same-package, zero-import references.
import handshake.node.util.HexUtil;
import handshake.node.urkeltree.UrkelNodeStore;

/** Shared scratch-RocksDB wiring for DiskBackedHashKeySet and
 *  DiskBackedOrphanQueue -- both are Set&lt;HashKey&gt; implementations
 *  backed by a temporary, on-disk RocksDB instance rather than JVM heap,
 *  for the same underlying reason (bounded memory on modest hardware --
 *  see each subclass's own comment for its specific, real-production
 *  problem). Before this class existed, both independently duplicated
 *  the exact same scratch-directory lifecycle, RocksDBKVStore/KVMap
 *  wiring, add()/contains()/size()/close(), and recursive scratch-dir
 *  cleanup -- confirmed, line for line, identical except for the two
 *  real differences each subclass still owns on top of this base:
 *  remove() semantics (HashKey-typed vs Object-typed, with or without a
 *  boolean existed-before return), and whether identity equals()/
 *  hashCode() are needed (DiskBackedOrphanQueue's own fix comment
 *  explains why it specifically needs that override; DiskBackedHashKeySet
 *  never needed it and still doesn't).
 *
 *  Deliberately does NOT implement iterator() -- each subclass still
 *  throws its own UnsupportedOperationException with its own specific
 *  wording, since a real iterator() here would invite exactly the
 *  "materialize everything into memory" pattern both classes exist to
 *  avoid. */
abstract class DiskBackedHashKeyStoreBase
        extends java.util.AbstractSet<UrkelNodeStore.HashKey> implements AutoCloseable {
    private static final byte[] MARKER = new byte[0];

    protected final java.nio.file.Path scratchDir;
    protected final RocksDBKVStore store;
    protected final KVMap<String, byte[]> map;
    protected int size = 0;

    /** @param tempDirPrefix prefix for this instance's scratch directory
     *      (each subclass uses its own, distinct prefix, for easier
     *      identification on disk if one is ever left behind).
     *  @param mapName name of the RocksDB-backed map opened within it.
     *  @param blockCacheBytesOverride explicit block-cache size for this
     *      short-lived scratch store, or null to fall back to
     *      RocksDBKVStore's normal auto-detected sizing. DiskBackedHashKeySet
     *      and DiskBackedOrphanQueue deliberately differ on this -- see
     *      each one's own constructor comment. */
    protected DiskBackedHashKeyStoreBase(String tempDirPrefix, String mapName, Long blockCacheBytesOverride) {
        try {
            this.scratchDir = java.nio.file.Files.createTempDirectory(tempDirPrefix);
        } catch (java.io.IOException e) {
            throw new RuntimeException("Could not create a scratch directory for " + tempDirPrefix, e);
        }
        this.store = (blockCacheBytesOverride != null)
                ? new RocksDBKVStore(scratchDir.toString(), false, blockCacheBytesOverride)
                : new RocksDBKVStore(scratchDir.toString());
        this.map = store.openStringBytesMap(mapName);
    }

    @Override
    public boolean add(UrkelNodeStore.HashKey key) {
        String hex = HexUtil.encode(key.bytes);
        if (map.containsKey(hex)) return false;
        map.put(hex, MARKER);
        size++;
        return true;
    }

    @Override
    public boolean contains(Object o) {
        if (!(o instanceof UrkelNodeStore.HashKey key)) return false;
        return map.containsKey(HexUtil.encode(key.bytes));
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public void close() {
        store.close();
        deleteRecursive(scratchDir.toFile());
    }

    protected static void deleteRecursive(java.io.File dir) {
        java.io.File[] files = dir.listFiles();
        if (files != null) {
            for (java.io.File f : files) {
                if (f.isDirectory()) deleteRecursive(f);
                else f.delete();
            }
        }
        dir.delete();
    }
}