package handshake.node;

/**
 * Content-addressed storage for Urkel tree nodes -- each Internal/Leaf
 * node is stored keyed by its own hash, which never depends on
 * anything external to the node itself (that's what makes content
 * addressing work at all: identical content always produces the same
 * key, and a node's identity IS its hash). Backed by a KVMap the same
 * way every other piece of persistent state in this project already
 * is, rather than replicating Urkel's own flat-file format.
 *
 * A node's CHILDREN are stored as just their hashes (not the full
 * child subtree) -- reconstructing a node gives back Hash placeholders
 * for its children, which only get resolved into real Internal/Leaf
 * nodes lazily, on demand, when a tree traversal actually needs to go
 * further. This is what keeps startup cheap regardless of how large
 * the tree gets: nothing is eagerly loaded.
 */
public class UrkelNodeStore {

    private static final byte TYPE_INTERNAL = 1;
    private static final byte TYPE_LEAF = 2;

    private final KVMap<String, byte[]> store;

    public UrkelNodeStore(KVMap<String, byte[]> store) {
        this.store = store;
    }

    /** Runs an operation (specifically: a prune's full walk-then-
     *  remove) with exclusive access relative to the underlying
     *  store's own compact() -- see MVStoreKVMap's own comment for the
     *  full reasoning on why the walk itself, not just the removal,
     *  needs this protection. */
    public <T> T runExclusiveOfCompaction(java.util.function.Supplier<T> operation) {
        return store.runExclusiveOfCompaction(operation);
    }

    /** Persists a single Internal or Leaf node (not its children --
     *  callers walk the tree themselves and persist each node they
     *  encounter).
     *
     *  FIX: previously checked store.containsKey(key) before every
     *  single write, to skip redundant writes for content that was
     *  already stored -- but the one and only real caller (UrkelTree's
     *  own persist()) already guarantees, via each node's in-memory
     *  `persisted` flag, that THIS specific node object has never been
     *  written by this tree instance before calling put() at all. The
     *  only remaining scenario the containsKey() check could catch is
     *  a genuine hash coincidence (identical content already present
     *  under this key from elsewhere) -- and content-addressing means
     *  that's always safe to just overwrite with identical bytes, not
     *  something requiring a check-first. That check was a full read
     *  before every single write, silently doubling the number of
     *  database operations for every newly-created tree node -- a
     *  real, measured cost once confirmed via direct benchmarking
     *  against a realistic-scale tree, not just removed on theory
     *  alone. */
    public void put(UrkelNode node) {
        String key = hex(node.hash());
        store.put(key, encode(node));
    }

    /** Batches many node writes into a single, coordinated store
     *  operation -- see putAll()'s own comment for the fuller
     *  reasoning, and KVMap.putAll()'s own comment for why this
     *  matters specifically for a RocksDB-backed store (WriteBatch,
     *  avoiding one JNI round-trip per node). */
    public void putAll(java.util.List<UrkelNode> nodes) {
        if (nodes.isEmpty()) return;
        java.util.Map<String, byte[]> encoded = new java.util.LinkedHashMap<>();
        for (UrkelNode node : nodes) {
            encoded.put(hex(node.hash()), encode(node));
        }
        store.putAll(encoded);
    }

    private byte[] encode(UrkelNode node) {
        byte[] encoded;
        if (node.isInternal()) {
            UrkelNode.Internal in = (UrkelNode.Internal) node;
            byte[] prefixData = in.prefix.data;
            encoded = new byte[1 + 2 + prefixData.length + 32 + 32];
            int pos = 0;
            encoded[pos++] = TYPE_INTERNAL;
            encoded[pos++] = (byte) (in.prefix.size & 0xFF);
            encoded[pos++] = (byte) ((in.prefix.size >>> 8) & 0xFF);
            System.arraycopy(prefixData, 0, encoded, pos, prefixData.length);
            pos += prefixData.length;
            System.arraycopy(in.left.hash(), 0, encoded, pos, 32);
            pos += 32;
            System.arraycopy(in.right.hash(), 0, encoded, pos, 32);
        } else if (node.isLeaf()) {
            UrkelNode.Leaf lf = (UrkelNode.Leaf) node;
            encoded = new byte[1 + 32 + lf.value.length];
            encoded[0] = TYPE_LEAF;
            System.arraycopy(lf.key, 0, encoded, 1, 32);
            System.arraycopy(lf.value, 0, encoded, 33, lf.value.length);
        } else {
            throw new IllegalArgumentException("Only Internal/Leaf nodes are stored directly, got: " + node);
        }
        return encoded;
    }

    /** Resolves a Hash placeholder into the real node it refers to --
     *  the children of an Internal node it returns are themselves Hash
     *  placeholders, not yet resolved. Throws if the hash genuinely
     *  isn't in storage (a real, serious problem -- either data loss
     *  or a bug -- not something to silently paper over). */
    public UrkelNode resolve(byte[] hash) {
        String key = hex(hash);
        byte[] encoded = store.get(key);
        if (encoded == null) {
            throw new IllegalStateException(
                    "Missing Urkel tree node for hash " + key
                            + " -- either real data loss, or a bug in what got persisted");
        }

        int type = encoded[0];
        UrkelNode result;
        if (type == TYPE_INTERNAL) {
            int size = (encoded[1] & 0xFF) | ((encoded[2] & 0xFF) << 8);
            int prefixBytes = (size + 7) >>> 3;
            UrkelBits prefix = UrkelBits.alloc(size);
            System.arraycopy(encoded, 3, prefix.data, 0, prefixBytes);
            int pos = 3 + prefixBytes;
            byte[] leftHash = java.util.Arrays.copyOfRange(encoded, pos, pos + 32);
            pos += 32;
            byte[] rightHash = java.util.Arrays.copyOfRange(encoded, pos, pos + 32);
            result = new UrkelNode.Internal(prefix, new UrkelNode.Hash(leftHash), new UrkelNode.Hash(rightHash));        } else if (type == TYPE_LEAF) {
            byte[] key32 = java.util.Arrays.copyOfRange(encoded, 1, 33);
            byte[] value = java.util.Arrays.copyOfRange(encoded, 33, encoded.length);
            result = new UrkelNode.Leaf(key32, value);
        } else {
            throw new IllegalStateException("Unknown stored node type: " + type);
        }

        // Integrity check: recomputing the hash from the stored content
        // must reproduce exactly the hash we looked it up by. A
        // mismatch here means real disk corruption (or a serious bug)
        // silently feeding a wrong node into a proof or lookup --
        // worth the extra hash computation to catch immediately rather
        // than let propagate.
        if (!java.util.Arrays.equals(result.hash(), hash)) {
            throw new IllegalStateException(
                    "Corrupted Urkel tree node: stored content for " + key
                            + " hashes to " + hex(result.hash()) + " instead");
        }

        // A node just loaded from storage is, by definition, already
        // persisted -- marking it as such lets future persist walks
        // prune here immediately instead of re-confirming something
        // already known.
        if (result instanceof UrkelNode.Internal in) in.persisted = true;
        else if (result instanceof UrkelNode.Leaf lf) lf.persisted = true;

        return result;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** Compact, immutable wrapper around a 32-byte node hash, used only
     *  internally by the prune path's own bookkeeping (snapshotKeys(),
     *  UrkelTree.collectReachable(), pruneUnreachable()) -- never
     *  exposed through the KVMap<String,...> interface the rest of the
     *  project uses, so changing this representation has zero blast
     *  radius outside these three methods, confirmed by checking every
     *  real caller before making this change.
     *
     *  FIX: this whole path previously worked in 64-character hex
     *  Strings throughout -- roughly 150-200+ bytes of real JVM heap
     *  per entry once object header, char[] backing array, and String's
     *  own fields are all counted, versus the 32 raw bytes the hash
     *  actually needs. At the scale this now runs at (several million
     *  total keys -- live nodes plus not-yet-pruned garbage -- between
     *  prune cycles, confirmed directly via real prune logs), that
     *  overhead is not incidental: a direct, empirical benchmark at
     *  3,000,000 keys measured over 550MB for just two of the sets this
     *  path builds, reallocated fresh on every single prune cycle. This
     *  wrapper cuts per-entry cost roughly 3x by keeping the raw bytes
     *  instead of their hex text, with a precomputed hashCode so
     *  HashSet/contains() lookups don't need to rehash the array
     *  repeatedly. Hex strings are still decoded/encoded at the two
     *  boundaries where they're unavoidable (reading keys from the
     *  KVMap<String,...>-typed store, and building the final removal
     *  list for removeAll()) -- but those hex Strings are now
     *  short-lived, immediately eligible for GC, rather than retained
     *  for the entire walk the way the old Set<String> approach kept
     *  them. */
    static final class HashKey {
        final byte[] bytes;
        private final int precomputedHash;

        HashKey(byte[] bytes) {
            this.bytes = bytes;
            this.precomputedHash = java.util.Arrays.hashCode(bytes);
        }

        @Override public boolean equals(Object o) {
            return o instanceof HashKey && java.util.Arrays.equals(bytes, ((HashKey) o).bytes);
        }

        @Override public int hashCode() { return precomputedHash; }
    }

    private static byte[] unhex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    /** Eagerly materializes a true, point-in-time copy of every key
     *  currently in the store -- deliberately NOT a live view, since
     *  this is specifically meant to be captured once, before a
     *  potentially long-running background walk, and remain completely
     *  unaffected by whatever the main thread adds to the store
     *  afterward. See pruneUnreachable()'s own comment for why this
     *  matters.
     *
     *  Returns the compact HashKey form directly -- see HashKey's own
     *  comment for why, and note this is now a single materialization,
     *  not a copy-of-a-copy: the previous version wrapped an already-
     *  fully-materialized store.keySet() in a second, redundant new
     *  HashSet<>(...), needlessly doubling memory for the exact same
     *  data. */
    public java.util.Set<HashKey> snapshotKeys() {
        java.util.Set<HashKey> result = new java.util.HashSet<>();
        for (String hexKey : store.keySet()) {
            result.add(new HashKey(unhex(hexKey)));
        }
        return result;
    }

    /** Removes every stored node NOT in reachableHashes -- the
     *  companion to collectReachable() in UrkelTree. This store is
     *  content-addressed and append-only by construction (put() never
     *  overwrites, only adds), which mirrors real Urkel's own on-disk
     *  design, but without a periodic prune of unreachable history this
     *  grows without bound: every single covenant transaction rewrites
     *  a tree-depth's worth of nodes along its path to the root, and
     *  none of the superseded ones were ever being removed. Confirmed
     *  as the actual driver of both a real, observed 45GB database
     *  after only 65,000 blocks and a real, observed progressive
     *  slowdown in processing (a map growing into the millions of
     *  entries gets slower to read and write against, independent of
     *  the underlying engine's own version/chunk-level compaction,
     *  which only reclaims old VERSIONS of the SAME key -- it has no
     *  way to know that a different, still-technically-live key is
     *  logically obsolete).
     *  Safe to call only when reachableHashes is known-complete for
     *  every root this store still needs to serve (see
     *  UrkelNameTree.pruneUnreachable() for why immediately after a
     *  commit boundary is the one point where that's guaranteed true
     *  cheaply, since the live and committed roots briefly coincide
     *  there).
     *
     *  FIX: previously compared against store.keySet() read LIVE, at
     *  removal time -- unsafe now that this can run on a background
     *  thread while the main thread concurrently persists brand-new
     *  nodes from later blocks (see UrkelTree.pruneUnreachableFrom()'s
     *  own comment for the full reasoning). Takes an explicit,
     *  pre-captured key snapshot instead -- see snapshotKeys() -- so
     *  anything added after that snapshot was taken can never be a
     *  removal candidate here, regardless of its reachability.
     *
     *  The actual bulk-removal mechanics (previously inlined here as
     *  an H2-specific auto-commit-disabling trick) now live entirely
     *  inside KVMap.removeAll() -- this method no longer knows or
     *  cares whether that's implemented via MVStore-specific tuning, a
     *  RocksDB WriteBatch, or anything else; it just asks the store to
     *  remove a set of keys efficiently. Returns the number of entries
     *  actually removed. */
    public int pruneUnreachable(java.util.Set<HashKey> keySnapshot, java.util.Set<HashKey> reachableHashes) {
        java.util.List<String> toRemove = new java.util.ArrayList<>();
        for (HashKey key : keySnapshot) {
            if (!reachableHashes.contains(key)) {
                toRemove.add(hex(key.bytes));
            }
        }
        return store.removeAll(toRemove);
    }
}