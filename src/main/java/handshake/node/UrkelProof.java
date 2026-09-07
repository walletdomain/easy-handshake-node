package handshake.node;

import java.util.ArrayList;
import java.util.List;

/**
 * An Urkel tree proof, translated directly from real Urkel's proof.js
 * (read in full). Four distinct types, each proving something
 * different about a key against a known, trusted root hash:
 *
 *  - EXISTS:    the key genuinely maps to the carried value.
 *  - DEADEND:   the key's path leads to a genuinely empty subtree.
 *  - SHORT:     the key's path leads to an Internal node whose own
 *               compressed prefix doesn't match the key -- proving
 *               the key can't be there, via that Internal node's own
 *               real prefix/left/right.
 *  - COLLISION: the key's path leads to a real Leaf, but for a
 *               DIFFERENT key -- proving the queried key isn't there,
 *               via that other leaf's actual key and value hash.
 *
 * Only EXISTS is a positive/inclusion proof; the other three are all
 * genuine non-existence proofs, each reconstructing what the real tree
 * contains at that exact point rather than merely asserting absence.
 */
public class UrkelProof {

    public static final int TYPE_DEADEND = 0;
    public static final int TYPE_SHORT = 1;
    public static final int TYPE_COLLISION = 2;
    public static final int TYPE_EXISTS = 3;

    public static final int PROOF_OK = 0;
    public static final int PROOF_HASH_MISMATCH = 1;
    public static final int PROOF_SAME_KEY = 2;
    public static final int PROOF_SAME_PATH = 3;
    public static final int PROOF_NEG_DEPTH = 4;
    public static final int PROOF_PATH_MISMATCH = 5;
    public static final int PROOF_TOO_DEEP = 6;

    /** One sibling hash collected on the way down from the root,
     *  together with whatever compressed prefix led to it -- matches
     *  ProofNode in proof.js. */
    public static class ProofNode {
        public final UrkelBits prefix;
        public final byte[] hash;
        public ProofNode(UrkelBits prefix, byte[] hash) {
            this.prefix = prefix;
            this.hash = hash;
        }
    }

    public int type = TYPE_DEADEND;
    public int depth = 0;
    public final List<ProofNode> nodes = new ArrayList<>();

    // TYPE_SHORT fields
    public UrkelBits prefix;
    public byte[] left;
    public byte[] right;

    // TYPE_COLLISION fields
    public byte[] key;
    public byte[] hash; // the OTHER leaf's value hash, not its full leaf hash

    // TYPE_EXISTS field
    public byte[] value;

    public void push(UrkelBits prefix, byte[] hash) {
        nodes.add(new ProofNode(prefix, hash));
    }

    /**
     * Verifies this proof against a known, trusted root (e.g. a
     * treeRoot pulled from a validated block header) and a specific
     * key. Returns [code, value] -- code == PROOF_OK and a non-null
     * value means genuine, verified inclusion; PROOF_OK with a null
     * value means genuine, verified absence; anything else means the
     * proof itself is malformed or doesn't match the claimed root and
     * must be rejected outright, not treated as "probably fine."
     *
     * Translated directly from proof.js's verify(), preserving every
     * one of its sanity checks (PROOF_SAME_KEY, PROOF_SAME_PATH,
     * PROOF_PATH_MISMATCH, etc.) -- these aren't decorative, they're
     * what stops a maliciously-crafted non-existence proof from being
     * accepted for a key that's actually present, or vice versa.
     */
    public Object[] verify(byte[] root, byte[] key, int bits) {
        byte[] leaf;

        switch (type) {
            case TYPE_DEADEND:
                leaf = UrkelHash.ZERO;
                break;
            case TYPE_SHORT:
                if (prefix.has(key, depth)) return new Object[]{PROOF_SAME_PATH, null};
                leaf = UrkelHash.hashInternal(prefix, left, right);
                break;
            case TYPE_COLLISION:
                if (java.util.Arrays.equals(this.key, key)) return new Object[]{PROOF_SAME_KEY, null};
                leaf = UrkelHash.hashLeaf(this.key, this.hash);
                break;
            case TYPE_EXISTS:
                leaf = UrkelHash.hashValue(key, value);
                break;
            default:
                throw new IllegalStateException("Invalid proof type: " + type);
        }

        byte[] next = leaf;
        int depth = this.depth;

        // Traverse the collected sibling hashes bottom-up (right to
        // left in the list, since they were collected top-down while
        // proving), recombining into successively higher Internal-node
        // hashes exactly as hashInternal would during real tree
        // construction.
        for (int i = nodes.size() - 1; i >= 0; i--) {
            ProofNode pn = nodes.get(i);

            if (depth < pn.prefix.size + 1) return new Object[]{PROOF_NEG_DEPTH, null};
            depth -= 1;

            if (UrkelBits.hasBit(key, depth)) {
                next = UrkelHash.hashInternal(pn.prefix, pn.hash, next);
            } else {
                next = UrkelHash.hashInternal(pn.prefix, next, pn.hash);
            }

            depth -= pn.prefix.size;

            if (!pn.prefix.has(key, depth)) return new Object[]{PROOF_PATH_MISMATCH, null};
        }

        if (depth != 0) return new Object[]{PROOF_TOO_DEEP, null};
        if (!java.util.Arrays.equals(next, root)) return new Object[]{PROOF_HASH_MISMATCH, null};

        return new Object[]{PROOF_OK, value};
    }

    public static String codeName(int code) {
        return switch (code) {
            case PROOF_OK -> "PROOF_OK";
            case PROOF_HASH_MISMATCH -> "PROOF_HASH_MISMATCH";
            case PROOF_SAME_KEY -> "PROOF_SAME_KEY";
            case PROOF_SAME_PATH -> "PROOF_SAME_PATH";
            case PROOF_NEG_DEPTH -> "PROOF_NEG_DEPTH";
            case PROOF_PATH_MISMATCH -> "PROOF_PATH_MISMATCH";
            case PROOF_TOO_DEEP -> "PROOF_TOO_DEEP";
            default -> "PROOF_UNKNOWN_ERROR";
        };
    }
}