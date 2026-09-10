package handshake.node;

/**
 * An in-memory Urkel (Merklix/radix) tree, translated directly from
 * real Urkel's tree.js (read in full) -- the insert/get/prove logic is
 * faithful to the original; only the disk-backed lazy-loading layer
 * (Pointer, the Hash placeholder node type, FileStore/MemoryStore) is
 * left out, since this project keeps the tree in memory for now rather
 * than replicate Urkel's own on-disk flat-file format. If/when this
 * needs to scale to real Handshake mainnet's full name set without
 * holding it all in memory, that's a separate, later integration step
 * (naturally backed by this project's existing H2/MVStore, the same as
 * everywhere else) -- not a change to the hashing/proof logic itself,
 * which is what actually has to match the real network's consensus.
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

    /** Exposes a point-in-time key snapshot from the configured node
     *  store -- see UrkelNodeStore.snapshotKeys()'s own comment for
     *  what this is for. Callers (specifically UrkelNameTree.
     *  maybeCommit()) need to capture this SYNCHRONOUSLY, at the same
     *  instant as the committed root itself, and BEFORE submitting the
     *  actual prune to a background thread -- see
     *  pruneUnreachableFrom()'s own comment for the full reasoning on
     *  why that timing specifically matters and is not just a style
     *  preference. Empty set (not null, not an exception) if no node
     *  store is configured, matching pruneUnreachableFrom()'s own
     *  no-op-when-unconfigured behavior. */
    public java.util.Set<UrkelNodeStore.HashKey> snapshotStoreKeys() {
        return nodeStore == null ? java.util.Set.of() : nodeStore.snapshotKeys();
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
        return nodeStore.resolve(node.hash());
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
                return UrkelNode.Internal.from(parts[0], newLeaf, child, bit);
            }

            UrkelNode x = in.get(bit);
            UrkelNode y = in.get(!bit);
            UrkelNode z = insert(x, key, value, depth + 1);
            if (z == null) return null;
            return UrkelNode.Internal.from(in.prefix, z, y, bit);
        }

        // Leaf
        UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
        if (java.util.Arrays.equals(key, lf.key)) {
            if (java.util.Arrays.equals(value, lf.value)) return null; // genuine no-op
            return leaf(key, value); // same key, new value -- simple replace
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
                    return new UrkelNode.Internal(joined, yin.left, yin.right);
                }
                return side;
            }

            return UrkelNode.Internal.from(in.prefix, z, y, bit);
        }

        // Leaf
        UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
        if (!java.util.Arrays.equals(key, lf.key)) return null;
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
     *  traversal does. */
    public void collectReachable(UrkelNode node, java.util.Set<UrkelNodeStore.HashKey> out) {
        if (node.isNull()) return;
        node = resolve(node);
        UrkelNodeStore.HashKey key = new UrkelNodeStore.HashKey(node.hash());
        if (!out.add(key)) return; // already visited this subtree

        if (node.isInternal()) {
            UrkelNode.Internal in = (UrkelNode.Internal) node;
            collectReachable(in.left, out);
            collectReachable(in.right, out);
        }
        // Leaf nodes have no children to descend into.
    }

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
     *  by the same test afterward. Capturing keySnapshot at the same
     *  synchronous instant as `root` closes this precisely the way the
     *  original comment already intended for the walk's own duration,
     *  just correctly extended to cover the submission delay too.
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
    public PruneResult pruneUnreachableFrom(UrkelNode root, java.util.Set<UrkelNodeStore.HashKey> keySnapshot) {
        if (nodeStore == null) return new PruneResult(0, 0, 0);
        return nodeStore.runExclusiveOfCompaction(() -> {
            long walkStart = System.currentTimeMillis();
            java.util.Set<UrkelNodeStore.HashKey> reachable = new java.util.HashSet<>();
            collectReachable(root, reachable);
            long walkMillis = System.currentTimeMillis() - walkStart;

            long removeStart = System.currentTimeMillis();
            int removed = nodeStore.pruneUnreachable(keySnapshot, reachable);
            long removeMillis = System.currentTimeMillis() - removeStart;

            return new PruneResult(removed, walkMillis, removeMillis);
        });
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

    /** The tree's current root node reference -- cheap to hold onto
     *  (see proveFrom's own comment), useful for a caller that wants
     *  to snapshot "prove-able state as of right now" without copying
     *  the whole tree. */
    public UrkelNode snapshotRoot() {
        return root;
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
    }

    /** Convenience: persists from the tree's current live root. */
    public void persistLive() {
        persistFrom(root);
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
            return;
        }

        // Leaf
        UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
        if (lf.persisted) return;
        out.add(lf);
        lf.persisted = true;
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