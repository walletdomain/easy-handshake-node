package handshake.node;

import java.util.ArrayList;
import java.util.List;

/**
 * Partial merkle tree (BIP 37-style compact inclusion proof), adapted to
 * Handshake's own leaf/internal/empty hash primitives (see MerkleUtil).
 * Ported directly from real hsd source (lib/primitives/merkleblock.js's
 * fromMatches()/extractTree()) rather than assumed to match Bitcoin's
 * partial-merkle-tree structure exactly, though the tree-walking logic
 * itself (which nodes get expanded vs. collapsed into a single hash)
 * turned out to be the same well-known algorithm -- only the underlying
 * hash primitives differ (Handshake's Blake2b leaf/internal/empty
 * scheme, already verified elsewhere in this project, rather than
 * Bitcoin's SHA256d-with-duplication).
    * <p>
 * A proof lets a verifier confirm a specific set of transactions were
 * included in a specific block's merkle root, without needing every
 * transaction in that block -- only enough sibling hashes to
 * reconstruct the root.
 */
public class MerkleProof {

    public static class BuiltProof {
        public int totalTX;
        public List<byte[]> hashes = new ArrayList<>();
        public byte[] flags;
    }

    public static class ExtractedTree {
        public byte[] root;
        public List<byte[]> matches = new ArrayList<>();
        public List<Integer> indexes = new ArrayList<>();
        public boolean failed;
    }

    private static int width(int totalTX, int height) {
        return (totalTX + (1 << height) - 1) >>> height;
    }

    // ── Generation (matches real fromMatches()) ─────────────────────────────

    /**
     * Builds a compact proof that the transactions marked true in
     * `matches` are included in the tree over `leaves` (all txids in
     * the block, in order).
     */
    public static BuiltProof buildProof(List<byte[]> leaves, boolean[] matches) {
        int totalTX = leaves.size();
        List<Integer> bits = new ArrayList<>();
        List<byte[]> hashes = new ArrayList<>();

        int height = 0;
        while (width(totalTX, height) > 1) height++;

        traverseBuild(height, 0, leaves, matches, totalTX, bits, hashes);

        byte[] flags = new byte[(bits.size() + 7) / 8];
        for (int p = 0; p < bits.size(); p++) {
            if (bits.get(p) != 0) flags[p / 8] |= (byte) (1 << (p % 8));
        }

        BuiltProof proof = new BuiltProof();
        proof.totalTX = totalTX;
        proof.hashes = hashes;
        proof.flags = flags;
        return proof;
    }

    /** The full hash of a subtree, when no descendant in it is matched
     *  (so the proof only needs this one collapsed hash, not the whole
     *  subtree's contents). */
    private static byte[] subtreeHash(int height, int pos, List<byte[]> leaves, int totalTX) {
        if (height == 0) return MerkleUtil.hashLeaf(leaves.get(pos));
        byte[] left = subtreeHash(height - 1, pos * 2, leaves, totalTX);
        byte[] right = (pos * 2 + 1 < width(totalTX, height - 1))
                ? subtreeHash(height - 1, pos * 2 + 1, leaves, totalTX)
                : MerkleUtil.EMPTY_HASH;
        return MerkleUtil.hashInternal(left, right);
    }

    private static void traverseBuild(int height, int pos, List<byte[]> leaves, boolean[] matches,
                                      int totalTX, List<Integer> bits, List<byte[]> hashes) {
        int parent = 0;
        int start = pos << height;
        int end = Math.min((pos + 1) << height, totalTX);
        for (int p = start; p < end; p++) {
            if (matches[p]) parent = 1;
        }
        bits.add(parent);

        if (height == 0 && parent != 0) {
            hashes.add(leaves.get(pos));
            return;
        }
        if (height == 0 || parent == 0) {
            hashes.add(subtreeHash(height, pos, leaves, totalTX));
            return;
        }

        traverseBuild(height - 1, pos * 2, leaves, matches, totalTX, bits, hashes);
        if (pos * 2 + 1 < width(totalTX, height - 1)) {
            traverseBuild(height - 1, pos * 2 + 1, leaves, matches, totalTX, bits, hashes);
        }
    }

    // ── Verification (matches real extractTree()) ───────────────────────────

    /** Mutable traversal state -- Java has no closures over primitives,
     *  so this plays the role of the JS traverse() closure's outer
     *  bitsUsed/hashUsed/failed variables. */
    private static class State {
        int bitsUsed, hashUsed;
        boolean failed;
    }

    /**
     * Reconstructs the merkle root (and the set of matched leaf hashes)
     * from a compact proof. Returns a tree with failed=true if the proof
     * is malformed or inconsistent -- callers should treat that the same
     * as "verification failed", matching real hsd's own behavior of
     * falling back to an empty PartialTree on any extraction error.
     */
    public static ExtractedTree extractTree(int totalTX, List<byte[]> hashes, byte[] flags) {
        ExtractedTree tree = new ExtractedTree();
        if (totalTX == 0) { tree.failed = true; return tree; }

        State st = new State();
        int height = 0;
        while (width(totalTX, height) > 1) height++;

        byte[] root = traverseExtract(height, 0, totalTX, hashes, flags, st, tree);

        if (st.failed
                || ((st.bitsUsed + 7) / 8) != flags.length
                || st.hashUsed != hashes.size()) {
            tree.failed = true;
            return tree;
        }

        tree.root = root;
        return tree;
    }

    private static byte[] traverseExtract(int height, int pos, int totalTX,
                                          List<byte[]> hashes, byte[] flags,
                                          State st, ExtractedTree tree) {
        if (st.bitsUsed >= flags.length * 8) {
            st.failed = true;
            return new byte[32];
        }

        int parent = (flags[st.bitsUsed / 8] >>> (st.bitsUsed % 8)) & 1;
        st.bitsUsed++;

        if (height == 0 || parent == 0) {
            if (st.hashUsed >= hashes.size()) {
                st.failed = true;
                return new byte[32];
            }
            byte[] hash = hashes.get(st.hashUsed);
            st.hashUsed++;

            if (height == 0 && parent != 0) {
                tree.matches.add(hash);
                tree.indexes.add(pos);
                return MerkleUtil.hashLeaf(hash);
            }
            return hash;
        }

        byte[] left = traverseExtract(height - 1, pos * 2, totalTX, hashes, flags, st, tree);
        byte[] right = (pos * 2 + 1 < width(totalTX, height - 1))
                ? traverseExtract(height - 1, pos * 2 + 1, totalTX, hashes, flags, st, tree)
                : MerkleUtil.EMPTY_HASH;

        return MerkleUtil.hashInternal(left, right);
    }

    // ── Wire format (matches real hsd's MerkleBlock.write()/read()) ────────

    /** Serializes header(236) + totalTX(4 LE) + hashes[varint-count, 32
     *  each] + flags[varint-length-prefixed]. */
    public static byte[] serialize(byte[] header, BuiltProof proof) {
        int size = 236 + 4 + varintSize(proof.hashes.size()) + proof.hashes.size() * 32
                + varintSize(proof.flags.length) + proof.flags.length;
        byte[] buf = new byte[size];
        int pos = 0;
        System.arraycopy(header, 0, buf, pos, 236); pos += 236;
        pos = writeLE32(buf, pos, proof.totalTX);
        pos = writeVarint(buf, pos, proof.hashes.size());
        for (byte[] h : proof.hashes) {
            System.arraycopy(h, 0, buf, pos, 32); pos += 32;
        }
        pos = writeVarint(buf, pos, proof.flags.length);
        System.arraycopy(proof.flags, 0, buf, pos, proof.flags.length); pos += proof.flags.length;
        return buf;
    }

    public static class ParsedProof {
        public byte[] header;
        public int totalTX;
        public List<byte[]> hashes = new ArrayList<>();
        public byte[] flags;
    }

    public static ParsedProof deserialize(byte[] data) {
        ParsedProof p = new ParsedProof();
        int pos = 0;
        p.header = java.util.Arrays.copyOfRange(data, 0, 236); pos += 236;
        p.totalTX = (int) readLE32(data, pos); pos += 4;
        int hashCount = (int) readVarint(data, pos); pos += varintSize(hashCount);
        for (int i = 0; i < hashCount; i++) {
            p.hashes.add(java.util.Arrays.copyOfRange(data, pos, pos + 32));
            pos += 32;
        }
        int flagsLen = (int) readVarint(data, pos); pos += varintSize(flagsLen);
        p.flags = java.util.Arrays.copyOfRange(data, pos, pos + flagsLen);
        return p;
    }

    private static long readLE32(byte[] b, int pos) {
        return (b[pos] & 0xFFL) | ((b[pos+1] & 0xFFL) << 8)
                | ((b[pos+2] & 0xFFL) << 16) | ((b[pos+3] & 0xFFL) << 24);
    }
    private static int writeLE32(byte[] b, int pos, int v) {
        b[pos] = (byte) v; b[pos+1] = (byte) (v >>> 8);
        b[pos+2] = (byte) (v >>> 16); b[pos+3] = (byte) (v >>> 24);
        return pos + 4;
    }
    private static long readVarint(byte[] b, int pos) {
        int first = b[pos] & 0xFF;
        if (first < 0xFD) return first;
        if (first == 0xFD) return (b[pos+1] & 0xFFL) | ((b[pos+2] & 0xFFL) << 8);
        return readLE32(b, pos + 1);
    }
    private static int varintSize(int v) {
        if (v < 0xFD) return 1;
        if (v <= 0xFFFF) return 3;
        return 5;
    }
    private static int writeVarint(byte[] b, int pos, int v) {
        if (v < 0xFD) { b[pos] = (byte) v; return pos + 1; }
        b[pos] = (byte) 0xFD; b[pos+1] = (byte) v; b[pos+2] = (byte) (v >>> 8);
        return pos + 3;
    }
}