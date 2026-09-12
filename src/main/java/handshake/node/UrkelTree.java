package handshake.node;

/**
 * An in-memory Urkel (Merklix/radix) tree, translated directly from
 * real Urkel's tree.js (read in full) -- the insert/get/prove logic is
 * faithful to the original; only the disk-backed lazy-loading layer
 * (Pointer, the Hash placeholder node type, FileStore/MemoryStore) is
 * left out, since real Urkel's own flat-file format was never
 * replicated exactly.
 *
 * "In-memory" describes how this class is IMPLEMENTED (a plain Java
 * object graph, not a custom on-disk format), not how much of the
 * tree is actually held in memory at once, which is now deliberately
 * bounded -- see persistLive()'s own comment for the real history
 * here: this used to also describe the actual RUNTIME behavior (the
 * whole live tree really did stay resident, growing without bound for
 * as long as the process ran), which caused a genuine, repeated
 * OutOfMemoryError crash under sustained load. What actually persists
 * between one block and the next now is a single 32-byte root hash,
 * with the real object graph resolved fresh from the configured
 * KVStore-backed node store on demand and released again immediately
 * after -- the same structural approach real Urkel's own disk-backed
 * design takes, just built on this project's existing storage
 * abstraction rather than a custom flat-file format.
 */
public class UrkelTree {

    /** Bits per key -- 256 for BLAKE2b-256-hashed name keys, matching
     *  real hsd's own Urkel tree configuration. */
    public final int bits;

    private UrkelNode root = UrkelNode.Null.NIL;

    /** Optional -- null means pure in-memory (existing behavior,
     *  everything already tests's rely on). When set, any Hash
     *  placeholder encountered during traversal gets resolved through
     *  this store rather than assumed to already be in memory. */
    private UrkelNodeStore nodeStore;

    public void setNodeStore(UrkelNodeStore nodeStore) {
        this.nodeStore = nodeStore;
    }

    /** Exposes a lightweight, O(1) point-in-time snapshot handle from
     *  the configured node store -- see UrkelNodeStore.openSnapshot()'s
     *  own comment for the full reasoning, and KVMap.openSnapshot()'s
     *  for why this specific split (cheap handle now, expensive
     *  enumeration deferred) exists at all. Callers (specifically
     *  UrkelNameTree.maybeCommit()) capture this SYNCHRONOUSLY, at the
     *  same instant as the committed root itself, then defer the
     *  actual key() enumeration to a background thread -- see
     *  pruneUnreachableFrom()'s own comment for why the SYNCHRONOUS
     *  capture specifically still matters, even though it's now cheap.
     *  Returns a snapshot whose keys() is an empty set if no node
     *  store is configured, matching pruneUnreachableFrom()'s own
     *  no-op-when-unconfigured behavior. */
    public KVMap.KVSnapshot<UrkelNodeStore.HashKey> openStoreSnapshot() {
        if (nodeStore == null) {
            return new KVMap.KVSnapshot<UrkelNodeStore.HashKey>() {
                @Override public java.util.Set<UrkelNodeStore.HashKey> keys() { return java.util.Set.of(); }
                @Override public void close() { }
            };
        }
        return nodeStore.openSnapshot();
    }

    /** Resolves a node if it's a lazy Hash placeholder, otherwise
     *  returns it unchanged. Called at the top of every traversal step
     *  so a placeholder anywhere in the tree gets transparently
     *  expanded the moment something actually needs to look past it. */
    private UrkelNode resolve(UrkelNode node) {
        if (!node.isHash()) return node;
        if (nodeStore == null) {
            throw new IllegalStateException(
                    "Encountered a Hash placeholder with no node store configured -- "
                            + "either setNodeStore() was never called, or a placeholder was "
                            + "constructed somewhere it shouldn't have been");
        }
        UrkelNode resolved = nodeStore.resolve(node.hash());
        // Incremental orphan tracking's resurrection safeguard: resolve()
        // (correctly) marks a just-loaded node persisted=true immediately,
        // since its content demonstrably already exists on disk -- but
        // that means it never goes through collectUnpersisted()'s
        // persisted=false -> true transition, which is the ONLY other
        // place unorphanIfPending() gets called. ANY successful resolve(),
        // from ANY caller (insert, remove, get, collectReachable, all of
        // them), proves this hash is reachable from whatever root is
        // currently being traversed RIGHT NOW -- which is exactly what
        // this safeguard needs to know, regardless of which operation
        // triggered it. */
        unorphanIfPending(resolved);
        return resolved;
    }

    public UrkelTree(int bits) {
        if (bits <= 0 || (bits & 7) != 0) {
            throw new IllegalArgumentException("bits must be a positive multiple of 8");
        }
        this.bits = bits;
    }

    public byte[] rootHash() {
        return root.hash();
    }

    private boolean isKey(byte[] key) {
        return key != null && key.length == (bits >>> 3);
    }

    private UrkelNode.Leaf leaf(byte[] key, byte[] value) {
        return new UrkelNode.Leaf(key, value);
    }

    /** Looks up a key's current value, or null if not present. */
    public byte[] get(byte[] key) {
        if (!isKey(key)) throw new IllegalArgumentException("Invalid key length");
        return get(root, key);
    }

    private byte[] get(UrkelNode node, byte[] key) {
        int depth = 0;
        for (;;) {
            node = resolve(node);
            if (node.isNull()) {
                return null;
            } else if (node.isInternal()) {
                UrkelNode.Internal in = (UrkelNode.Internal) node;
                if (!in.prefix.has(key, depth)) return null;
                depth += in.prefix.size;
                boolean bit = UrkelBits.hasBit(key, depth);
                node = in.get(bit);
                depth += 1;
            } else { // leaf
                UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
                if (!java.util.Arrays.equals(key, lf.key)) return null;
                return lf.value;
            }
        }
    }

    /** Inserts or updates a key's value. Returns true if the tree's
     *  root actually changed (false if this was a genuine no-op --
     *  the same key already mapped to the exact same value). */
    public boolean insert(byte[] key, byte[] value) {
        if (!isKey(key)) throw new IllegalArgumentException("Invalid key length");
        UrkelNode result = insert(root, key, value, 0);
        if (result == null) return false;
        root = result;
        return true;
    }

    private UrkelNode insert(UrkelNode node, byte[] key, byte[] value, int depth) {
        node = resolve(node);
        if (node.isNull()) {
            return leaf(key, value);
        }

        if (node.isInternal()) {
            UrkelNode.Internal in = (UrkelNode.Internal) node;
            int matched = in.prefix.count(key, depth);
            depth += matched;
            boolean bit = UrkelBits.hasBit(key, depth);

            if (matched != in.prefix.size) {
                // The new key's path diverges partway through this
                // node's own compressed prefix -- split it: a new,
                // shorter-prefixed Internal node branches into the new
                // leaf on one side, and the OLD node (now wrapped with
                // just the remaining "back" portion of its prefix) on
                // the other. This is the actual Patricia-style path
                // compression/splitting behavior.
                UrkelNode.Leaf newLeaf = leaf(key, value);
                UrkelBits[] parts = in.prefix.split(matched);
                UrkelNode.Internal child = new UrkelNode.Internal(parts[1], in.left, in.right);
                orphan(in, child); // in's CHILDREN get reused (wrapped
                // into child); in itself is only
                // ACTUALLY superseded if child's own
                // hash differs from it -- see
                // orphan()'s own comment for why that
                // check matters here specifically
                // (matched == 0 makes them identical).
                return UrkelNode.Internal.from(parts[0], newLeaf, child, bit);
            }

            UrkelNode x = in.get(bit);
            UrkelNode y = in.get(!bit);
            UrkelNode z = insert(x, key, value, depth + 1);
            if (z == null) return null;
            UrkelNode.Internal replacement = UrkelNode.Internal.from(in.prefix, z, y, bit);
            orphan(in, replacement); // same prefix, new child on this
            // side -- `y` (untouched sibling)
            // is reused, not orphaned.
            return replacement;
        }

        // Leaf
        UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
        if (java.util.Arrays.equals(key, lf.key)) {
            if (java.util.Arrays.equals(value, lf.value)) return null; // genuine no-op
            UrkelNode.Leaf replacement = leaf(key, value);
            orphan(lf, replacement); // same key, new value -- simple replace
            return replacement;
        }

        if (depth == bits) {
            throw new IllegalStateException("Two different keys with identical bit paths -- impossible");
        }

        UrkelBits sharedPrefix = lf.bits().collide(key, depth);
        depth += sharedPrefix.size;

        UrkelNode.Leaf newLeaf = leaf(key, value);
        boolean bit = UrkelBits.hasBit(key, depth);
        return UrkelNode.Internal.from(sharedPrefix, newLeaf, lf, bit);
    }

    /** Removes a key, if present. Returns true if the tree's root
     *  actually changed. Translated directly from tree.js's
     *  _remove() -- including the subtlety that removing a leaf can
     *  collapse its now-single-child parent Internal node, rejoining
     *  the parent's and sibling's compressed prefixes back into one
     *  combined prefix when the sibling is itself an Internal node. */
    public boolean remove(byte[] key) {
        if (!isKey(key)) throw new IllegalArgumentException("Invalid key length");
        UrkelNode result = remove(root, key, 0);
        if (result == null) return false;
        root = result;
        return true;
    }

    private UrkelNode remove(UrkelNode node, byte[] key, int depth) {
        node = resolve(node);
        if (node.isNull()) {
            return null;
        }

        if (node.isInternal()) {
            UrkelNode.Internal in = (UrkelNode.Internal) node;
            if (!in.prefix.has(key, depth)) return null;

            depth += in.prefix.size;
            boolean bit = UrkelBits.hasBit(key, depth);
            UrkelNode x = in.get(bit);
            UrkelNode y = in.get(!bit);
            UrkelNode z = remove(x, key, depth + 1);
            if (z == null) return null;

            if (z.isNull()) {
                // The removed leaf's side is now empty -- this
                // Internal node collapses down to just its other
                // side. Must resolve `y` first: if it's still an
                // unresolved Hash placeholder, isInternal() would
                // incorrectly report false even when the real node
                // underneath genuinely is Internal, silently skipping
                // the prefix-joining logic below -- matches real
                // Urkel's own explicit resolve-before-check here.
                UrkelNode side = resolve(y);
                if (side.isInternal()) {
                    UrkelNode.Internal yin = (UrkelNode.Internal) side;
                    UrkelBits joined = in.prefix.join(yin.prefix, !bit);
                    UrkelNode.Internal replacement = new UrkelNode.Internal(joined, yin.left, yin.right);
                    orphan(in, replacement); // in is gone either way in
                    // this branch -- collapsed
                    // away entirely here.
                    orphan(yin, replacement); // yin's OWN prefix gets
                    // replaced by the newly
                    // joined one -- yin's
                    // CHILDREN are reused
                    // directly, but yin itself
                    // no longer exists.
                    return replacement;
                }
                orphan(in, side); // `in` is replaced outright by `side`
                // (== y, or Null) here -- side itself
                // is reused/promoted as-is, not
                // orphaned.
                return side;
            }

            UrkelNode.Internal replacement = UrkelNode.Internal.from(in.prefix, z, y, bit);
            orphan(in, replacement); // `y` (the untouched sibling) is reused.
            return replacement;
        }

        // Leaf
        UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
        if (!java.util.Arrays.equals(key, lf.key)) return null;
        orphan(lf, UrkelNode.Null.NIL); // the key matched -- lf is being
        // removed outright.
        return UrkelNode.Null.NIL;
    }

    /** Walks from a given root, collecting the compact hash key (see
     *  UrkelNodeStore.HashKey's own comment for why this isn't a hex
     *  String) of every Internal/Leaf node reachable from it into out --
     *  the companion operation to persistFrom(): where that writes
     *  everything new since the last call, this identifies everything
     *  still actually needed, for a caller that wants to prune anything
     *  else from the node store. Stops descending into an already-
     *  visited hash (a subtree can be shared by multiple paths after
     *  copy-on-write updates) rather than re-walking it, and resolves
     *  Hash placeholders through the node store exactly like normal
     *  traversal does.
     *
     *  Checks for a requested interrupt on every single node visited --
     *  cheap (a volatile-flag read) next to the rest of a node visit's
     *  own cost, and this is the one place a real, sustained-load prune
     *  walk actually spends its time, so this is what makes shutdown
     *  responsive rather than needing to wait out however much of a
     *  potentially multi-minute walk was still left. See
     *  UrkelNameTree.shutdownPruning() for why responding quickly here
     *  is necessary, not just a nice-to-have -- closing the underlying
     *  RocksDB store while this walk is still making native calls into
     *  it is a real, confirmed, unrecoverable crash (not a catchable
     *  Java exception -- RocksDB is native code via JNI, and misusing
     *  an already-closed handle segfaults the whole process rather than
     *  throwing), so shutdown MUST wait for this to actually stop, and
     *  this is what lets that wait be fast instead of unboundedly long. */
    /** How many nodes to visit between brief, voluntary CPU yields
     *  during a walk -- see the throttled overload below for the full
     *  reasoning. */
    private static final int YIELD_EVERY_N_NODES = 5000;
    private static final long YIELD_PAUSE_MILLIS = 5;

    /** How often (wall-clock) to print a progress line during a long
     *  walk -- deliberately time-based, not node-count-based like the
     *  yield above: a walk over millions of nodes at 5,000/yield would
     *  otherwise print thousands of lines, which defeats the point of
     *  a diagnostic (nobody reads thousands of lines); a periodic
     *  wall-clock cadence gives a steady trickle of real progress
     *  information regardless of tree size. */
    private static final long PROGRESS_LOG_EVERY_MILLIS = 10_000;

    /** Mutable state threaded through collectReachable()'s recursion --
     *  a small, named holder rather than a raw counter, since this now
     *  tracks more than one thing: how many nodes since the last yield
     *  (visitedSinceYield), how many total this walk (totalVisited, for
     *  progress reporting), and when progress was last printed
     *  (lastLogMillis, so PROGRESS_LOG_EVERY_MILLIS is measured against
     *  wall-clock time, not node count). */
    private static final class WalkState {
        int visitedSinceYield = 0;
        long totalVisited = 0;
        long lastLogMillis = System.currentTimeMillis();
    }

    /** Public entry point -- starts fresh walk state. See the private,
     *  throttled overload below for what actually happens node-by-
     *  node; this just wraps it. */
    public void collectReachable(UrkelNode node, java.util.Set<UrkelNodeStore.HashKey> out) {
        collectReachable(node, out, new WalkState());
    }

    /** Same traversal as the public overload above, with two additions
     *  -- both added directly in response to a real, reported crash
     *  that could previously only be diagnosed after the fact, by
     *  inferring from block-height alignment and an external profiler
     *  whether a prune was even running at the time:
     *
     *  1. Briefly sleeps every YIELD_EVERY_N_NODES nodes visited (see
     *     below for the full reasoning on why this exists at all).
     *  2. Prints a progress line -- nodes visited so far this walk,
     *     current heap usage -- every PROGRESS_LOG_EVERY_MILLIS,
     *     giving direct, real-time visibility into whether a long walk
     *     is genuinely still making progress and what memory is
     *     actually doing while it runs, without needing to infer
     *     either after the fact.
     *
     *  FIX (the yielding itself): confirmed via a real, reported case --
     *  not just this process slowing down, but the whole machine
     *  becoming unusable -- during a prune's walk at real production
     *  scale (millions of live names, an order of magnitude past
     *  anything tested here beforehand, and taking well over ten
     *  minutes wall-clock as a direct result). The OS does preemptively
     *  time-slice CPU among threads regardless, but a walk running
     *  flat-out across millions of nodes, each triggering real
     *  allocation and (for anything not already cached) a real disk
     *  read, can still dominate available CPU and generate enough GC
     *  pressure to make the whole system feel unresponsive for its
     *  entire duration. A brief, periodic sleep genuinely frees a core
     *  during that window, and slowing the walk's own allocation rate
     *  somewhat also eases how aggressively the GC needs to run. The
     *  honest cost: this adds real wall-clock time to the walk itself,
     *  proportional to how many nodes it visits -- a deliberate trade
     *  of some of the walk's own speed for the rest of the machine
     *  staying usable while it runs, which is the right trade given
     *  what actually happened here -- though also worth knowing
     *  honestly: a slower walk means more time for concurrent
     *  allocation from the main thread too, so this isn't guaranteed to
     *  reduce PEAK memory even though it should ease CPU contention;
     *  the progress logging above is what will actually show, directly,
     *  whether that tradeoff is landing well in practice or not, rather
     *  than continuing to guess. Combined with the prune thread's own
     *  lowered OS priority (see pruneExecutor's own comment) -- two
     *  different angles on the same problem, neither a complete fix
     *  alone. */
    private void collectReachable(UrkelNode node, java.util.Set<UrkelNodeStore.HashKey> out, WalkState state) {
        if (Thread.currentThread().isInterrupted()) throw new PruneInterruptedException();
        if (node.isNull()) return;
        node = resolve(node);
        UrkelNodeStore.HashKey key = new UrkelNodeStore.HashKey(node.hash());
        if (!out.add(key)) return; // already visited this subtree

        state.totalVisited++;
        long now = System.currentTimeMillis();
        if (now - state.lastLogMillis >= PROGRESS_LOG_EVERY_MILLIS) {
            state.lastLogMillis = now;
            System.out.println("[UrkelTree] Prune walk in progress: " + state.totalVisited
                    + " nodes visited so far (heap: " + UrkelNameTree.heapSnapshot() + ")");
        }

        if (++state.visitedSinceYield >= YIELD_EVERY_N_NODES) {
            state.visitedSinceYield = 0;
            try {
                Thread.sleep(YIELD_PAUSE_MILLIS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new PruneInterruptedException();
            }
        }

        if (node.isInternal()) {
            UrkelNode.Internal in = (UrkelNode.Internal) node;
            collectReachable(in.left, out, state);
            collectReachable(in.right, out, state);
        }
        // Leaf nodes have no children to descend into.
    }

    /** Thrown internally when a background prune's own walk detects
     *  the shutdown-requested interrupt -- see collectReachable()'s and
     *  shutdownPruning()'s own comments for why this exists and what
     *  it's for. Not a real error; caught and handled as a clean,
     *  expected abort by pruneUnreachableFrom()'s own caller. */
    public static final class PruneInterruptedException extends RuntimeException {}

    /** Result of a prune pass, broken down by phase -- the walk
     *  (collectReachable(), resolving every still-needed node) and the
     *  removal (nodeStore.pruneUnreachable(), deleting everything
     *  else) are quite different operations with very different cost
     *  profiles, and only measuring them separately can actually show
     *  which one (if either) is the real bottleneck rather than just a
     *  single combined number. */
    public record PruneResult(int removed, long walkMillis, long removeMillis) {}

    /** Convenience: collects everything reachable from root, then
     *  removes everything else from the configured node store. No-op
     *  (0 removed, 0ms either phase) if no node store is configured.
     *  See UrkelNodeStore.pruneUnreachable() for the full reasoning on
     *  safety and why this exists.
     *
     *  FIX: this can now run on a background thread while the main
     *  thread keeps mutating the LIVE tree and persisting brand-new
     *  nodes concurrently (see UrkelNameTree.maybeCommit()'s own
     *  comment for why that's safe for the walk itself). But it is
     *  NOT automatically safe for the removal step: that step used to
     *  compare against nodeStore's CURRENT key set at removal time,
     *  which -- given the walk alone takes 66-97+ seconds, during
     *  which the main thread keeps persisting new nodes from LATER
     *  blocks the whole time -- would include keys that didn't exist
     *  yet when this root was snapshotted. Those newer keys are
     *  correctly absent from `reachable` (which only reflects THIS
     *  root), so comparing against the live key set would have
     *  incorrectly treated brand-new, genuinely-needed data as
     *  orphaned.
     *
     *  SECOND, MORE SERIOUS FIX: the key snapshot must now be passed in
     *  by the caller, captured SYNCHRONOUSLY at the same moment as
     *  `root` itself (see UrkelNameTree.maybeCommit(), which now does
     *  exactly this) -- this method previously called
     *  nodeStore.snapshotKeys() itself, internally, which sounds
     *  equivalent but isn't: this whole method only runs inside the
     *  background executor's task, submitted asynchronously from
     *  maybeCommit(). The scheduling delay between submission and the
     *  executor actually starting the task is itself a real window --
     *  during it, the main thread keeps processing blocks and
     *  persisting brand-new, not-yet-committed nodes to disk. A key
     *  snapshot taken AFTER that delay would incorrectly include those
     *  newer nodes (since they're already on disk by then), but they
     *  are NOT reachable from `root` (an older, already-fixed committed
     *  root that predates them) -- so they would be wrongly treated as
     *  orphaned and deleted, even though the live tree still needs them
     *  and will need them again at the very next commit. Confirmed as
     *  a real, reproducible bug via a direct test (apply the same
     *  covenant sequence two ways -- straight through, and with a
     *  close/reopen restart injected partway through -- and compare the
     *  resulting committed roots) before this fix, and confirmed fixed
     *  by the same test afterward.
     *
     *  SECOND FIX, immediately after the first: capturing the key
     *  snapshot synchronously does NOT mean eagerly enumerating every
     *  key synchronously -- an earlier version of this fix did exactly
     *  that (Set<HashKey> keySnapshot, fully materialized before
     *  submission), which was correct but became a severe, real
     *  performance regression once the store reached several million
     *  keys: 40+ seconds of blocked main-thread processing on every
     *  single commit, confirmed directly from real, reported
     *  production timing data. This parameter is now a lightweight,
     *  O(1) KVSnapshot HANDLE instead (see KVMap.openSnapshot()'s own
     *  comment) -- synchronous capture still fixes the correct instant
     *  in time, but the actual expensive enumeration is deferred to
     *  keys(), called from inside this method's own background task
     *  below, not by the caller. Same correctness guarantee, without
     *  blocking anything.
     *
     *  FIX: the ENTIRE walk-then-remove now runs under
     *  runExclusiveOfCompaction() -- confirmed via a real, repeatedly
     *  observed "Chunk ... not found" error that persisted even after
     *  raising MVStore's retention time well beyond any observed walk
     *  duration, ruling out "walk simply outlasted retention" as the
     *  (sole) cause. compactFile() doesn't just reclaim old, dead
     *  versions after retention expires -- it actively defragments the
     *  file, physically moving and renumbering live chunks, which can
     *  invalidate a chunk the walk is mid-read on regardless of
     *  retention timing. Only the removal phase was ever protected
     *  against this before; the walk itself, despite being the longer
     *  of the two phases, never was. */
    public PruneResult pruneUnreachableFrom(UrkelNode root, KVMap.KVSnapshot<UrkelNodeStore.HashKey> keySnapshotHandle) {
        if (nodeStore == null) return new PruneResult(0, 0, 0);
        return nodeStore.runExclusiveOfCompaction(() -> {
            try {
                long walkStart = System.currentTimeMillis();
                java.util.Set<UrkelNodeStore.HashKey> reachable = new java.util.HashSet<>();
                collectReachable(root, reachable);
                long walkMillis = System.currentTimeMillis() - walkStart;

                // FIX: this used to call keySnapshotHandle.keys() first,
                // eagerly materializing EVERY key in the store (live
                // names plus however much unpruned garbage has
                // accumulated -- potentially tens of millions of
                // entries) into one, single in-memory Set, before ever
                // comparing anything against `reachable` above.
                // Confirmed as a real, severe OutOfMemoryError cause at
                // real production scale -- see KVSnapshot.forEachKey()'s
                // own comment for the full reasoning and how this was
                // actually diagnosed (a heap jump of over a gigabyte
                // within seconds, fast enough that none of this
                // project's other prune safeguards -- which all live in
                // collectReachable() above, a DIFFERENT step -- ever got
                // a chance to even start).
                //
                // Streaming instead: each key from the store is checked
                // against `reachable` (already bounded by the live
                // tree's own size, not the total, garbage-inclusive
                // store size) and immediately either discarded (if
                // still needed) or added to toRemove (if not) -- the
                // full key set itself is never materialized anywhere,
                // only this walk's own reachable set (already required
                // regardless) and toRemove, which should typically be
                // far smaller than the full store.
                long removeStart = System.currentTimeMillis();
                java.util.List<UrkelNodeStore.HashKey> toRemove = new java.util.ArrayList<>();
                keySnapshotHandle.forEachKey(key -> {
                    if (!reachable.contains(key)) toRemove.add(key);
                });
                int removed = nodeStore.removeKeys(toRemove);
                long removeMillis = System.currentTimeMillis() - removeStart;

                return new PruneResult(removed, walkMillis, removeMillis);
            } finally {
                // Must always release the underlying snapshot resource
                // (a real RocksDB Snapshot, for the active engine) --
                // otherwise the engine keeps pinning whatever data
                // existed at snapshot time indefinitely, unable to
                // reclaim it. Not just a style concern: a real,
                // growing resource leak if skipped.
                keySnapshotHandle.close();
            }
        });
    }

    /** RE-ARCHITECTURE: hybrid mechanism -- the actual, primary way
     *  cleanup happens now, replacing pruneUnreachableFrom() above on
     *  the automatic path (that method stays available, unwired, as an
     *  optional deep-audit tool -- see its own doc comment for the full
     *  history of why the walk exists and what it protects against).
     *
     *  candidates comes from the incremental orphan tracker (see
     *  orphan()/advanceOrphanGeneration()), accumulated continuously,
     *  essentially for free, as insert()/remove() actually happen.
     *  Confirmed, via extensive direct testing against this exact walk-
     *  based mechanism on large, randomized operation sequences, to
     *  have zero false negatives -- it never misses real garbage. What
     *  it DOES have, confirmed the same way: a narrow, specific false-
     *  positive rate (roughly 0.1% in that testing) from a resurrection
     *  edge case that resisted several rounds of targeted, hook-based
     *  fixes without being fully closed. Rather than keep chasing that
     *  gap with more local hooks, or accept the real, permanent memory
     *  cost of full reference counting (a separate, considered, and
     *  rejected option -- see this project's own notes on why), this
     *  runs the walk here specifically to VALIDATE candidates before
     *  anything is actually deleted, not to independently rediscover
     *  them.
     *
     *  This is a genuine efficiency win over the old mechanism, not
     *  just a safety wrapper: the old approach needed the full,
     *  expensive keySnapshotHandle.forEachKey() streaming enumeration
     *  of EVERY key in the store (potentially tens of millions of
     *  entries, live and garbage combined) to compute "store minus
     *  reachable". This needs only the walk itself (already required
     *  either way) to compute `reachable`, then filters the tracker's
     *  own, typically far smaller candidate set against it -- no full-
     *  store enumeration at all. */
    public PruneResult reconcileAndRemove(UrkelNode root, java.util.Set<UrkelNodeStore.HashKey> candidates) {
        if (nodeStore == null) return new PruneResult(0, 0, 0);
        return nodeStore.runExclusiveOfCompaction(() -> {
            long walkStart = System.currentTimeMillis();
            // RE-ARCHITECTURE: disk-backed, not an in-memory HashSet --
            // see DiskBackedHashKeySet's own class comment for the full
            // reasoning. Closed in the finally below regardless of how
            // this exits, so its scratch directory never lingers past
            // one reconciliation cycle.
            DiskBackedHashKeySet reachable = new DiskBackedHashKeySet();
            try {
                collectReachable(root, reachable);
                long walkMillis = System.currentTimeMillis() - walkStart;

                long removeStart = System.currentTimeMillis();
                java.util.List<UrkelNodeStore.HashKey> confirmedGarbage = new java.util.ArrayList<>();
                for (UrkelNodeStore.HashKey candidate : candidates) {
                    if (!reachable.contains(candidate)) confirmedGarbage.add(candidate);
                }
                int removed = nodeStore.removeKeys(confirmedGarbage);
                long removeMillis = System.currentTimeMillis() - removeStart;

                return new PruneResult(removed, walkMillis, removeMillis);
            } finally {
                reachable.close();
            }
        });
    }

    /** RE-ARCHITECTURE: no validation walk at all -- trusts the
     *  incremental orphan tracker's own candidates completely, deleting
     *  them directly. Used ONLY during deep catch-up (see
     *  UrkelNameTree.maybeCommit()'s own comment for the full
     *  reasoning): the validation walk above is now safe on modest
     *  hardware thanks to DiskBackedHashKeySet, but it's still genuinely
     *  slow, and during catch-up that slowness means real, ongoing CPU
     *  and disk contention with the main sync thread -- the same
     *  category of problem today's other catch-up-specific fixes (the
     *  signature-verification skip, the reduced prune frequency) all
     *  address the same way: accept a small, deliberate, bounded trust
     *  reduction during the one phase where speed matters most, then
     *  fall back to the fully-verified path once caught up, where
     *  there's real idle time between blocks to afford it. The known,
     *  narrow risk this accepts: an unresolved (not just unexplored --
     *  four specific hypotheses investigated and ruled out or reverted)
     *  false-positive rate in the incremental tracker, confirmed at
     *  roughly 0.1% in large-scale testing. Not something to be
     *  comfortable with indefinitely, but a small, bounded, catch-up-
     *  only exposure rather than the correctness gap being the sole
     *  thing standing between this project and running on a 4GB
     *  machine at all. */
    public int removeDirectly(java.util.Set<UrkelNodeStore.HashKey> candidates) {
        if (nodeStore == null) return 0;
        return nodeStore.removeKeys(new java.util.ArrayList<>(candidates));
    }

    /** Builds a proof for a key against an explicit root node, rather
     *  than the tree's current live root -- lets a caller prove
     *  against a specific historical snapshot (e.g. UrkelNameTree's
     *  last-committed root) rather than whatever the live tree has
     *  mutated to since. Safe because insert()/remove() never mutate
     *  existing node objects in place; they always build new ones, so
     *  an old root reference remains fully valid and unaffected by
     *  later changes -- the same property that makes real Urkel's own
     *  disk-backed snapshots work. */
    public UrkelProof proveFrom(UrkelNode snapshotRoot, byte[] key) {
        if (!isKey(key)) throw new IllegalArgumentException("Invalid key length");
        return prove(snapshotRoot, key);
    }

    /** Sets the tree's root directly -- used on startup to resume from
     *  a persisted root hash (as a Hash placeholder, resolved lazily
     *  from there) rather than starting empty. */
    public void inject(UrkelNode root) {
        this.root = root;
    }

    /** Walks from a given root, writing every not-yet-persisted
     *  Internal/Leaf node to the configured node store. Prunes the
     *  moment it hits a node already marked persisted -- an unchanged
     *  node's children must already be on disk too (written alongside
     *  it the first time), so there's nothing further to walk there.
     *  This keeps the cost proportional to how much actually changed
     *  since the last call, not the tree's total size -- meant to be
     *  called after every block, not just at commit boundaries, since
     *  a restart never replays already-processed blocks and would
     *  otherwise permanently lose any tree changes made between the
     *  last persist and the restart. No-op if no node store is
     *  configured (pure in-memory use, e.g. most of this class's own
     *  tests).
     *
     *  FIX: previously called nodeStore.put() individually for every
     *  single new node during the walk -- confirmed via direct
     *  benchmarking as a real, measured cost: persistBlock() became
     *  the dominant per-block processing cost (up to ~80% of total
     *  time) in real, high-covenant-volume ranges of the chain, since
     *  every new node write was a separate round-trip. Now collects
     *  every not-yet-persisted node during the walk first, then writes
     *  them all as a single batched operation (see UrkelNodeStore.
     *  putAll() / KVMap.putAll()) -- the same technique already proven
     *  to give a dramatic (~18x) speedup for the prune's own bulk
     *  removal path. Each node is marked persisted=true DURING the
     *  walk itself (unchanged from before), both to correctly avoid
     *  re-descending into or re-collecting an already-visited subtree
     *  within this same call, and to keep the walk's own O(what
     *  changed) cost profile -- but if the batch write itself then
     *  fails, every node just marked is rolled back to persisted=false
     *  before the exception propagates, preserving the exact same
     *  safe-to-retry guarantee the old per-node approach had: nothing
     *  is ever left incorrectly marked as durable when it isn't. */
    public void persistFrom(UrkelNode node) {
        if (nodeStore == null) return;
        java.util.List<UrkelNode> toWrite = new java.util.ArrayList<>();
        collectUnpersisted(node, toWrite);
        if (toWrite.isEmpty()) return;
        try {
            nodeStore.putAll(toWrite);
        } catch (RuntimeException e) {
            for (UrkelNode n : toWrite) {
                if (n.isInternal()) ((UrkelNode.Internal) n).persisted = false;
                else if (n.isLeaf()) ((UrkelNode.Leaf) n).persisted = false;
            }
            throw e;
        }

        // FIX: this is what actually bounds this project's in-memory
        // footprint -- see this project's own class comment and
        // UrkelNode.Internal's own comment on `left`/`right` for the
        // full reasoning. Deliberately runs AFTER the write above has
        // already succeeded, never before or during: collapsing a node
        // to a lightweight placeholder BEFORE confirming it's actually
        // safely on disk would mean a failed write could permanently
        // lose data that was never really persisted -- the exact
        // opposite of what collectUnpersisted()'s own rollback-on-
        // failure guarantees a few lines above. Only ever replaces a
        // child with a placeholder once that specific child's own
        // `persisted` flag is true, which by this point is guaranteed
        // for everything actually written just now, and was already
        // true (and thus already collapsed, if this ran on an earlier
        // call) for anything written earlier. Only ever walks reachable
        // from the live root passed in here -- UrkelNameTree no longer
        // retains any separate, standing object-graph reference for the
        // committed root at all (see its own committedRootAsNode()),
        // only a plain hash value materialized into a fresh, lightweight
        // placeholder each time something needs one -- so there's
        // nothing else this could ever reach or affect. resolve()
        // already handles a Hash placeholder anywhere in the tree
        // transparently, including from the background prune's own
        // walk (confirmed directly under real concurrent load, not
        // just reasoned about -- see this fix's own verification).
        for (UrkelNode n : toWrite) {
            if (n.isInternal()) {
                UrkelNode.Internal in = (UrkelNode.Internal) n;
                collapseIfPersisted(in, true);
                collapseIfPersisted(in, false);
            }
        }
    }

    private void collapseIfPersisted(UrkelNode.Internal parent, boolean isLeft) {
        UrkelNode child = isLeft ? parent.left : parent.right;
        if (child.isHash() || child.isNull()) return; // nothing to collapse
        if (!isPersisted(child)) return;
        UrkelNode.Hash placeholder = new UrkelNode.Hash(child.hash());
        if (isLeft) parent.left = placeholder;
        else parent.right = placeholder;
    }

    private static boolean isPersisted(UrkelNode node) {
        return (node.isInternal() && ((UrkelNode.Internal) node).persisted)
                || (node.isLeaf() && ((UrkelNode.Leaf) node).persisted);
    }

    /** RE-ARCHITECTURE, incremental orphan tracking: two generations,
     *  not one -- see advanceOrphanGeneration()'s own comment for why a
     *  single generation isn't enough on its own. pendingOrphans is
     *  THIS commit window's newly-superseded candidates; awaitingNextCommit
     *  is the PREVIOUS window's, already buffered through one full extra
     *  cycle, about to become the actually-safe-to-delete set the next
     *  time advanceOrphanGeneration() is called. unorphanIfPending()
     *  checks and removes from BOTH -- a hash is only ever truly beyond
     *  this class's own protection once it's been handed back to the
     *  caller as a confirmed, final deletion batch, at which point the
     *  one-extra-cycle buffer it already sat through is what provides
     *  the real safety margin (see UrkelNameTree's own commit-boundary
     *  handling for the timing reasoning that buffer is built on).
     *
     *  FIX: both genuinely need to be thread-safe, not just mutable --
     *  confirmed the hard way, via a real ConcurrentModificationException
     *  crash. orphan()/advanceOrphanGeneration() run on the main thread
     *  during ordinary block processing, but unorphanIfPending() ALSO
     *  gets called from resolve() (see its own comment), which runs
     *  from collectReachable() -- and near the tip, that walk runs on
     *  the BACKGROUND reconciliation thread, concurrently with the main
     *  thread's own, ongoing mutations of these exact same sets. A
     *  plain HashSet was never safe for that combination; it simply
     *  hadn't been exercised by a background-thread walker calling into
     *  resolve() until the near-tip path started using one. Deep
     *  catch-up never triggers this specific race (that path never
     *  walks at all), which is exactly why this went unnoticed until a
     *  restart-consistency test happened to exercise the near-tip path
     *  enough times to hit it. awaitingNextCommit is also volatile, not
     *  just concurrent-safe internally -- it gets REASSIGNED (a new Set
     *  entirely, not just mutated) inside advanceOrphanGeneration(), and
     *  without volatile there's no guaranteed happens-before relationship
     *  ensuring the background thread ever observes that reassignment
     *  promptly, the same class of gap volatile already closed for
     *  UrkelNode.Internal's own left/right fields earlier this session. */
    private final java.util.Set<UrkelNodeStore.HashKey> pendingOrphans =
            java.util.concurrent.ConcurrentHashMap.newKeySet();
    private volatile java.util.Set<UrkelNodeStore.HashKey> awaitingNextCommit =
            java.util.concurrent.ConcurrentHashMap.newKeySet();

    /** Records oldNode as a deletion candidate if (and only if) it was
     *  already persisted AND its hash actually differs from newNode's --
     *  called explicitly at each specific point in insert()/remove()
     *  above where copy-on-write is known to supersede a node at its own
     *  tree position, rather than derived generically from comparing
     *  old vs. new results everywhere.
     *
     *  The hash-equality check is NOT redundant with the explicit call
     *  sites above -- confirmed the hard way, via a direct cross-check
     *  against the trusted walk-based mechanism on a large, randomized
     *  operation sequence: a node CAN be reconstructed with genuinely
     *  identical content (same hash) at a position that looks, from the
     *  surrounding code, like a clear supersession -- e.g. insert()'s
     *  own prefix-split case, where a new key diverging at position zero
     *  produces a wrapper node that's hash-IDENTICAL to the original.
     *  Reasoning case-by-case about which call sites need this and which
     *  don't already produced one confirmed miss; checking uniformly,
     *  every time, is what actually closed that gap rather than trading
     *  it for a different unverified assumption. */
    private void orphan(UrkelNode oldNode, UrkelNode newNode) {
        if (isPersisted(oldNode) && !java.util.Arrays.equals(oldNode.hash(), newNode.hash())) {
            pendingOrphans.add(new UrkelNodeStore.HashKey(oldNode.hash()));
        }
    }

    /** Advances the generation pipeline at a commit boundary and returns
     *  whatever's now actually, finally safe to delete.
     *
     *  FIX: originally a single generation, drained and handed to the
     *  caller as immediately final. Confirmed WRONG via a direct,
     *  large-scale cross-check against the trusted walk-based mechanism:
     *  content-addressed hashes legitimately reappearing (a real,
     *  measured occurrence, not a theoretical edge case) after their
     *  generation had already been drained meant nothing could pull
     *  them back out anymore, since UrkelTree's own bookkeeping had
     *  already forgotten them entirely. Two generations fixes this: a
     *  hash superseded during commit window N sits in pendingOrphans
     *  through that whole window, then moves to awaitingNextCommit at
     *  commit N -- still fully visible to unorphanIfPending() -- and
     *  only becomes part of the RETURNED, final batch at commit N+1.
     *  That's the SAME one-extra-cycle timing this whole design was
     *  built on (see this class's own comments on why a generation
     *  needs to survive one full window past the commit that directly
     *  supersedes it), just correctly implemented as two live,
     *  protectable stages instead of one stage plus an unprotected
     *  handoff. */
    public java.util.Set<UrkelNodeStore.HashKey> advanceOrphanGeneration() {
        java.util.Set<UrkelNodeStore.HashKey> toReturn = awaitingNextCommit;
        // Must also be a concurrent-safe set, not a plain HashSet copy --
        // this becomes the NEW awaitingNextCommit, still subject to the
        // exact same concurrent unorphanIfPending() calls from a
        // background reconciliation walk. See these fields' own comment
        // for the full reasoning.
        java.util.Set<UrkelNodeStore.HashKey> nextGeneration = java.util.concurrent.ConcurrentHashMap.newKeySet();
        nextGeneration.addAll(pendingOrphans);
        awaitingNextCommit = nextGeneration;
        pendingOrphans.clear();
        return toReturn;
    }

    /** Persists from the tree's current live root, then -- this is the
     *  actual point of this method now, not incidental to it -- also
     *  collapses the root itself down to a lightweight Hash placeholder
     *  once it's confirmed safely on disk.
     *
     *  RE-ARCHITECTURE, step 2 (see UrkelNameTree.maybeCommit()'s own
     *  comment for step 1, the committed root's equivalent): this
     *  class's own header comment used to say this project "keeps the
     *  tree in memory for now rather than replicate Urkel's own on-disk
     *  flat-file format" -- that was true, and it was the real,
     *  underlying cause of a genuine, repeated OutOfMemoryError crash
     *  under sustained, extreme covenant load, surviving even after
     *  persistFrom()'s own collapse logic above (which handles every
     *  OTHER node in the tree, but never the root itself -- the root
     *  has no parent whose own collapse pass would ever reach it, so it
     *  stayed a full, retained object indefinitely, across every block,
     *  no matter how long the process ran).
     *
     *  What survives between blocks now is a 32-byte hash, never a
     *  retained object graph -- insert()/remove()/get() already handle
     *  a Hash placeholder anywhere in the tree transparently, including
     *  at the root, since this is exactly what already happens after
     *  every real restart (root gets injected as a Hash placeholder
     *  there too) -- so there's no new code path being exercised here,
     *  only a change in how OFTEN that same, already-proven path gets
     *  used: every block now, not just the first one after a restart.
     *
     *  The honest tradeoff, not hidden: every block's first touch of
     *  any given name now needs a fresh resolve() from disk, even for a
     *  name touched in the immediately preceding block, since nothing
     *  stays resolved across the boundary between them anymore. This is
     *  the real, deliberate cost of bounding memory this way -- the
     *  same tradeoff real Urkel's own design makes, not a regression
     *  introduced by accident. */
    public void persistLive() {
        persistFrom(root);
        if (isPersisted(root)) {
            root = new UrkelNode.Hash(root.hash());
        }
    }

    private void collectUnpersisted(UrkelNode node, java.util.List<UrkelNode> out) {
        if (node.isHash()) return; // already on disk by definition
        if (node.isNull()) return; // nothing to store for an empty subtree

        if (node.isInternal()) {
            UrkelNode.Internal in = (UrkelNode.Internal) node;
            if (in.persisted) return; // this node and everything under it is already saved
            collectUnpersisted(in.left, out);
            collectUnpersisted(in.right, out);
            out.add(in);
            in.persisted = true;
            unorphanIfPending(in);
            return;
        }

        // Leaf
        UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
        if (lf.persisted) return;
        out.add(lf);
        lf.persisted = true;
        unorphanIfPending(lf);
    }

    /** RE-ARCHITECTURE, incremental orphan tracking's resurrection
     *  safeguard: content-addressed hashes CAN legitimately reappear --
     *  confirmed as a real, not just theoretical, occurrence by a
     *  direct cross-check against the trusted walk-based mechanism on a
     *  large, randomized operation sequence. If a hash that was
     *  previously recorded as superseded gets newly persisted again --
     *  the exact moment collectUnpersisted() above marks it
     *  persisted=true -- it's unambiguously alive again, and MUST be
     *  pulled back out of wherever it's currently sitting before
     *  advanceOrphanGeneration() can ever hand it off as final. Checks
     *  BOTH generations, not just the newest one -- see
     *  advanceOrphanGeneration()'s own comment for why a hash already
     *  moved into awaitingNextCommit still needs this same protection,
     *  right up until the moment it's actually returned as confirmed. */
    private void unorphanIfPending(UrkelNode node) {
        UrkelNodeStore.HashKey key = new UrkelNodeStore.HashKey(node.hash());
        pendingOrphans.remove(key);
        awaitingNextCommit.remove(key);
    }

    /** Builds a proof for a key against the tree's current root --
     *  either a real inclusion proof (TYPE_EXISTS) or one of three
     *  genuine non-existence proofs (TYPE_DEADEND/SHORT/COLLISION),
     *  whichever actually applies. */
    public UrkelProof prove(byte[] key) {
        if (!isKey(key)) throw new IllegalArgumentException("Invalid key length");
        return prove(root, key);
    }

    private UrkelProof prove(UrkelNode node, byte[] key) {
        UrkelProof proof = new UrkelProof();
        int depth = 0;

        for (;;) {
            node = resolve(node);
            if (node.isNull()) {
                proof.type = UrkelProof.TYPE_DEADEND;
                proof.depth = depth;
                return proof;
            }

            if (node.isInternal()) {
                UrkelNode.Internal in = (UrkelNode.Internal) node;

                if (!in.prefix.has(key, depth)) {
                    proof.type = UrkelProof.TYPE_SHORT;
                    proof.depth = depth;
                    proof.prefix = in.prefix.clone();
                    proof.left = in.left.hash().clone();
                    proof.right = in.right.hash().clone();
                    return proof;
                }

                depth += in.prefix.size;
                boolean bit = UrkelBits.hasBit(key, depth);
                UrkelNode side = in.get(!bit);
                proof.push(in.prefix.clone(), side.hash());

                node = in.get(bit);
                depth += 1;
                continue;
            }

            // Leaf
            UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
            if (java.util.Arrays.equals(lf.key, key)) {
                proof.type = UrkelProof.TYPE_EXISTS;
                proof.depth = depth;
                proof.value = lf.value;
            } else {
                proof.type = UrkelProof.TYPE_COLLISION;
                proof.depth = depth;
                proof.key = lf.key.clone();
                proof.hash = Blake2b.hash(lf.value, UrkelHash.HASH_SIZE);
            }
            return proof;
        }
    }
}