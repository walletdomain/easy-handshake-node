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

    /** Walks from a given root, collecting the hex-encoded hash of
     *  every Internal/Leaf node reachable from it into out -- the
     *  companion operation to persistFrom(): where that writes
     *  everything new since the last call, this identifies everything
     *  still actually needed, for a caller that wants to prune anything
     *  else from the node store. Stops descending into an already-
     *  visited hash (a subtree can be shared by multiple paths after
     *  copy-on-write updates) rather than re-walking it, and resolves
     *  Hash placeholders through the node store exactly like normal
     *  traversal does. */
    public void collectReachable(UrkelNode node, java.util.Set<String> out) {
        if (node.isNull()) return;
        node = resolve(node);
        String key = UrkelNodeStore.hex(node.hash());
        if (!out.add(key)) return; // already visited this subtree

        if (node.isInternal()) {
            UrkelNode.Internal in = (UrkelNode.Internal) node;
            collectReachable(in.left, out);
            collectReachable(in.right, out);
        }
        // Leaf nodes have no children to descend into.
    }

    /** Convenience: collects everything reachable from root, then
     *  removes everything else from the configured node store. No-op
     *  (returns 0) if no node store is configured. See
     *  UrkelNodeStore.pruneUnreachable() for the full reasoning on
     *  safety and why this exists. */
    public int pruneUnreachableFrom(UrkelNode root) {
        if (nodeStore == null) return 0;
        java.util.Set<String> reachable = new java.util.HashSet<>();
        collectReachable(root, reachable);
        return nodeStore.pruneUnreachable(reachable);
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
     *  tests). */
    public void persistFrom(UrkelNode node) {
        if (nodeStore == null) return;
        persist(node);
    }

    /** Convenience: persists from the tree's current live root. */
    public void persistLive() {
        persistFrom(root);
    }

    private void persist(UrkelNode node) {
        if (node.isHash()) return; // already on disk by definition
        if (node.isNull()) return; // nothing to store for an empty subtree

        if (node.isInternal()) {
            UrkelNode.Internal in = (UrkelNode.Internal) node;
            if (in.persisted) return; // this node and everything under it is already saved
            persist(in.left);
            persist(in.right);
            nodeStore.put(in);
            in.persisted = true;
            return;
        }

        // Leaf
        UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
        if (lf.persisted) return;
        nodeStore.put(lf);
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