package handshake.node;

/** A Set<HashKey> backed by a temporary, on-disk RocksDB instance,
 *  rather than JVM heap.
 *
 *  RE-ARCHITECTURE: a reconciliation walk's reachable set, at real
 *  production scale (millions of live tree nodes), is a multi-
 *  gigabyte structure that needs to persist in memory for the walk's
 *  entire, potentially long duration -- confirmed directly, via real,
 *  reported production runs, to reach 5-7GB and climb toward an 8GB
 *  heap ceiling. Fine on a machine with plenty of spare RAM; a real,
 *  disqualifying problem on the kind of modest hardware (as little as
 *  4GB total system RAM) this project explicitly wants to support --
 *  many real Handshake nodes run on exactly that.
 *
 *  This trades some walk speed (a disk read/write per node instead of
 *  an in-memory hash operation) for a small, bounded memory footprint
 *  regardless of total tree size -- the same kind of trade already
 *  made elsewhere in this project (periodic yielding, streaming key
 *  enumeration) for the same underlying reason: real correctness and
 *  real safety on modest hardware matter more here than raw speed on
 *  powerful hardware.
 *
 *  Created fresh for exactly one reconciliation cycle's walk, in the
 *  OS's own temp directory (no new plumbing needed to thread the main
 *  data directory through here) -- and wiped entirely via close()
 *  once that cycle finishes, success or failure. Never accumulates
 *  across cycles; nothing here is meant to survive past a single
 *  walk.
 *
 *  Deliberately does NOT support iteration or arbitrary Set methods --
 *  only what collectReachable()'s own add()-based dedup check and
 *  reconcileAndRemove()'s own contains()-based candidate filtering
 *  actually need. A real iterator() here would invite exactly the
 *  "materialize everything into memory" pattern this class exists to
 *  avoid. */
final class DiskBackedHashKeySet extends java.util.AbstractSet<UrkelNodeStore.HashKey> implements AutoCloseable {
    private static final byte[] MARKER = new byte[0];

    private final java.nio.file.Path scratchDir;
    private final RocksDBKVStore store;
    private final KVMap<String, byte[]> map;
    private int size = 0;

    DiskBackedHashKeySet() {
        try {
            this.scratchDir = java.nio.file.Files.createTempDirectory("urkel-reachability-");
        } catch (java.io.IOException e) {
            throw new RuntimeException("Could not create a scratch directory for the reachability walk", e);
        }
        this.store = new RocksDBKVStore(scratchDir.toString());
        this.map = store.openStringBytesMap("reachable");
    }

    @Override
    public boolean add(UrkelNodeStore.HashKey key) {
        String hex = hex(key.bytes);
        if (map.containsKey(hex)) return false;
        map.put(hex, MARKER);
        size++;
        return true;
    }

    @Override
    public boolean contains(Object o) {
        if (!(o instanceof UrkelNodeStore.HashKey key)) return false;
        return map.containsKey(hex(key.bytes));
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public java.util.Iterator<UrkelNodeStore.HashKey> iterator() {
        throw new UnsupportedOperationException(
                "DiskBackedHashKeySet intentionally supports only add()/contains() -- "
                        + "see this class's own comment for why iteration isn't offered.");
    }

    @Override
    public void close() {
        store.close();
        deleteRecursive(scratchDir.toFile());
    }

    private static void deleteRecursive(java.io.File dir) {
        java.io.File[] files = dir.listFiles();
        if (files != null) {
            for (java.io.File f : files) {
                if (f.isDirectory()) deleteRecursive(f);
                else f.delete();
            }
        }
        dir.delete();
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}