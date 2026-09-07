package handshake.node;

import org.h2.mvstore.MVMap;

/**
 * Content-addressed storage for Urkel tree nodes -- each Internal/Leaf
 * node is stored keyed by its own hash, which never depends on
 * anything external to the node itself (that's what makes content
 * addressing work at all: identical content always produces the same
 * key, and a node's identity IS its hash). Backed by an MVMap the same
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

    private final MVMap<String, byte[]> store;

    public UrkelNodeStore(MVMap<String, byte[]> store) {
        this.store = store;
    }

    /** Persists a single Internal or Leaf node (not its children --
     *  callers walk the tree themselves and persist each node they
     *  encounter). A no-op if this exact content is already stored,
     *  since content-addressing means an existing entry under this key
     *  is guaranteed to already be byte-identical. */
    public void put(UrkelNode node) {
        String key = hex(node.hash());
        if (store.containsKey(key)) return; // already stored, and guaranteed identical

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

        store.put(key, encoded);
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

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}