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
 *  Created fresh in the OS's own temp directory (no new plumbing
 *  needed to thread the main data directory through here) -- and
 *  wiped entirely via close() once its owner is done with it.
 *
 *  UPDATE: originally "its owner is done with it" meant "this one
 *  reconciliation cycle's walk", with a fresh instance per cycle and
 *  never anything surviving across cycles. That was the real cause of
 *  the walk needing to re-visit the ENTIRE live tree from the root
 *  every single cycle, forever, with cost growing unboundedly as the
 *  tree grows -- confirmed as a real production problem (a single
 *  walk exceeding an hour, still running, at real mainnet-scale name
 *  counts). See UrkelTree's own persistentReachable field comment for
 *  the fix: an instance of this class can now be kept alive and
 *  reused across many cycles instead, in which case "its owner is
 *  done with it" means the tree's owner is shutting down, not just
 *  finishing one cycle. Nothing in this class itself needed to change
 *  for that -- it was always just a Set with a few methods; only how
 *  long callers choose to keep one alive changed.
 *
 *  RE-ARCHITECTURE: the scratch-directory/RocksDB/KVMap wiring and the
 *  add()/contains()/size()/close() methods now live in the shared
 *  DiskBackedHashKeyStoreBase, since DiskBackedOrphanQueue needed the
 *  exact same wiring for its own, separately documented reason -- see
 *  that base class's own comment. Only what's genuinely specific to
 *  this class (the scratch block-cache override, remove(), and the
 *  iterator()-is-unsupported message) still lives here.
 *
 *  Deliberately does NOT support iteration or arbitrary Set methods --
 *  only what collectReachable()'s own add()-based dedup check and
 *  reconcileAndRemove()'s own contains()-based candidate filtering
 *  actually need. A real iterator() here would invite exactly the
 *  "materialize everything into memory" pattern this class exists to
 *  avoid. */
final class DiskBackedHashKeySet extends DiskBackedHashKeyStoreBase {

    /** FIX: this used to let RocksDBKVStore auto-detect its block cache
     *  size from TOTAL SYSTEM RAM (up to a 4GB ceiling) -- the right
     *  choice for the one long-lived chain database, completely wrong
     *  for this class. This set exists for exactly one reconciliation
     *  walk (opened fresh roughly every 360 blocks near the tip, then
     *  closed) and only ever does add()/contains() against short
     *  32-byte keys -- it gets no real benefit from a cache sized for a
     *  permanent, multi-gigabyte database, and paying for one anyway,
     *  repeatedly, was real, confirmed native (off-heap, invisible to
     *  -Xmx and to JVM heap monitoring) memory pressure severe enough to
     *  make a whole machine unusable during a long sync, independent of
     *  -- and much larger than -- whatever the JVM heap number reported
     *  at the time. 32MB is generous for what this actually stores. */
    private static final long SCRATCH_BLOCK_CACHE_BYTES = 32L * 1024 * 1024;

    DiskBackedHashKeySet() {
        super("urkel-reachability-", "reachable", SCRATCH_BLOCK_CACHE_BYTES);
    }

    /** FIX: added so this set can be kept alive and reused ACROSS
     *  reconciliation cycles (see UrkelTree's own persistentReachable
     *  field comment for why) instead of being thrown away and rebuilt
     *  from scratch every single cycle. A long-lived reachable set
     *  needs a way to drop an entry that's stopped being reachable --
     *  without this, every hash ever seen as reachable even once would
     *  stay "reachable" in this set forever, which would make pruning
     *  silently stop collecting real garbage after the first walk. Not
     *  needed by the original, one-shot-per-walk design this class
     *  shipped with (a set that's discarded after every walk has
     *  nothing to evict from), which is why it wasn't here before.
     *  Safe to call on a key that was never present -- a harmless
     *  no-op, matching java.util.Set's own contract for remove(). */
    public boolean remove(UrkelNodeStore.HashKey key) {
        String hex = HexUtil.encode(key.bytes);
        if (!map.containsKey(hex)) return false;
        map.remove(hex);
        size--;
        return true;
    }

    @Override
    public java.util.Iterator<UrkelNodeStore.HashKey> iterator() {
        throw new UnsupportedOperationException(
                "DiskBackedHashKeySet intentionally supports only add()/contains() -- "
                        + "see this class's own comment for why iteration isn't offered.");
    }
}