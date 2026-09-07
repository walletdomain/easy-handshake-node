package handshake.node;

/**
 * Urkel tree node types, translated directly from real Urkel's
 * nodes.js. Deliberately simplified from the original: this omits the
 * "Hash" placeholder node type and Pointer/on-disk-offset machinery
 * real Urkel uses for lazily loading subtrees from its own flat-file
 * storage -- this project keeps the tree in memory for now (see
 * UrkelTree's own class comment for the scope decision), so there's
 * nothing to lazily resolve yet. The three node types that actually
 * affect the computed hash (Null, Internal, Leaf) are translated
 * faithfully; only the storage-lazy-loading layer is left out.
 */
public abstract class UrkelNode {

    public abstract byte[] hash();

    public boolean isNull()     { return false; }
    public boolean isInternal() { return false; }
    public boolean isLeaf()     { return false; }
    public boolean isHash()     { return false; }

    /** Null (empty subtree) -- singleton, matching real Urkel's NIL. */
    public static final class Null extends UrkelNode {
        public static final Null NIL = new Null();
        private Null() {}

        @Override public byte[] hash() { return UrkelHash.ZERO; }
        @Override public boolean isNull() { return true; }
    }

    /** A lazy placeholder holding just a node's hash -- the piece that
     *  makes disk-backed lazy loading possible. Real Urkel's own Hash
     *  node works the same way (see nodes.js): it doesn't know or care
     *  whether it's really an Internal or a Leaf underneath, it's just
     *  a stand-in until something actually needs the real subtree,
     *  at which point a resolver looks it up by this hash. */
    public static final class Hash extends UrkelNode {
        public final byte[] hash;
        public Hash(byte[] hash) { this.hash = hash; }
        @Override public byte[] hash() { return hash; }
        @Override public boolean isHash() { return true; }
    }

    public static final class Internal extends UrkelNode {
        public final UrkelBits prefix;
        public UrkelNode left;
        public UrkelNode right;
        private byte[] cachedHash;
        /** Bookkeeping only, not part of this node's identity/hash --
         *  lets persistence prune a walk the moment it hits a node
         *  already known to be on disk, since (by the same
         *  copy-on-write property that makes proveFrom's snapshots
         *  safe) an unchanged node's children must already be
         *  persisted too, having been written alongside it the first
         *  time. */
        boolean persisted = false;

        public Internal(UrkelBits prefix, UrkelNode left, UrkelNode right) {
            this.prefix = prefix;
            this.left = left;
            this.right = right;
        }

        /** Sets left/right by bit value (0=left, 1=right), matching
         *  Internal.get/set/from in nodes.js -- used when splitting a
         *  prefix during insert, where "which side" is computed as a
         *  bit rather than known statically. */
        public UrkelNode get(boolean bit) { return bit ? right : left; }
        public void set(boolean bit, UrkelNode node) {
            if (bit) right = node; else left = node;
        }

        public static Internal from(UrkelBits prefix, UrkelNode x, UrkelNode y, boolean bit) {
            Internal node = new Internal(prefix, Null.NIL, Null.NIL);
            node.set(bit, x);
            node.set(!bit, y);
            return node;
        }

        @Override
        public byte[] hash() {
            // Cached, exactly like real Urkel's Internal.hash() --
            // recomputing on every access would be needlessly
            // expensive for a tree that's queried far more often than
            // it's mutated.
            if (cachedHash == null) {
                cachedHash = UrkelHash.hashInternal(prefix, left.hash(), right.hash());
            }
            return cachedHash;
        }

        @Override public boolean isInternal() { return true; }
    }

    public static final class Leaf extends UrkelNode {
        public final byte[] key;
        public final byte[] value;
        private final byte[] hash;
        boolean persisted = false;

        /** Matches Tree.leaf(key, value) in tree.js -- the leaf's hash
         *  is computed EAGERLY at construction (via hashValue), not
         *  lazily like Internal's, since there's nothing else to wait
         *  for: a leaf's hash only ever depends on its own key/value,
         *  never on other nodes. */
        public Leaf(byte[] key, byte[] value) {
            this.key = key;
            this.value = value;
            this.hash = UrkelHash.hashValue(key, value);
        }

        /** Treats this leaf's own full key as a Bits object covering
         *  every bit of it -- matches nodes.js's "get bits()", used
         *  during insert to find how many more bits a new key shares
         *  with this leaf's key beyond the depth already matched. */
        public UrkelBits bits() {
            return UrkelBits.from(key);
        }

        @Override public byte[] hash() { return hash; }
        @Override public boolean isLeaf() { return true; }
    }
}