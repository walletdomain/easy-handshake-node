package handshake.node;

import java.util.Arrays;
import java.util.List;

/**
 * Builds and verifies Handshake's merkle root over a block's
 * transactions.
    * <p>
 * This is a DIFFERENT, and separately important, check from header
 * validation (HeaderUtil.chainsFrom()/checkPOW()). Header validation
 * proves the HEADER is legitimate -- correctly chained, and backed by
 * genuine proof-of-work. It says nothing about whether the actual
 * transaction data a peer sends in a block response corresponds to that
 * header at all. A peer could send a genuinely valid, correctly-mined
 * header (accepted during header sync) alongside completely fabricated
 * transaction/UTXO data in the block response, and without this check
 * that fabricated data would be processed as if it were legitimate.
 * Verifying the merkle root closes that gap: it proves the specific
 * transactions received are exactly the ones the (already-validated)
 * header committed to.
    * <p>
 * Algorithm (RFC 6962 / RFC 7574 style, per hsd-dev.org/protocol/merkle.html):
 *   EMPTY_HASH = Blake2b-256(empty buffer)
 *   Leaf:       Blake2b-256(0x00 || txid)
 *   Internal:   Blake2b-256(0x01 || left || right)
 *   Odd node at any level: paired with EMPTY_HASH, NOT duplicated
 *   (unlike Bitcoin's power-of-two padding, which duplicates the last node)
    * <p>
 * NOTE: this algorithm was ported from a secondary reference and, given
 * that same reference has been wrong before elsewhere in this project
 * (ACT_THREE_SIZE, a mislabeled genesis hash), it should be treated as
 * unverified until checked against real captured block data -- the same
 * standard applied to everything else here.
 */
public class MerkleUtil {

    public static final byte[] EMPTY_HASH = Blake2b.hash(new byte[0], 32);

    /** Leaf hash: Blake2b-256(0x00 || txid). Exposed for MerkleProof's
     *  partial-tree logic, which needs the same primitives. */
    public static byte[] hashLeaf(byte[] txid) {
        byte[] leaf = new byte[33];
        leaf[0] = 0x00;
        System.arraycopy(txid, 0, leaf, 1, 32);
        return Blake2b.hash(leaf, 32);
    }

    /** Internal node hash: Blake2b-256(0x01 || left || right). */
    public static byte[] hashInternal(byte[] left, byte[] right) {
        byte[] node = new byte[65];
        node[0] = 0x01;
        System.arraycopy(left, 0, node, 1, 32);
        System.arraycopy(right, 0, node, 33, 32);
        return Blake2b.hash(node, 32);
    }

    /** Computes the merkle root over a list of txids (32 bytes each). */
    public static byte[] buildRoot(List<byte[]> txids) {
        if (txids.isEmpty()) return EMPTY_HASH.clone();

        byte[][] level = new byte[txids.size()][];
        for (int i = 0; i < txids.size(); i++) {
            level[i] = hashLeaf(txids.get(i));
        }

        while (level.length > 1) {
            int pairCount = (level.length + 1) / 2;
            byte[][] next = new byte[pairCount][];
            for (int i = 0; i < pairCount; i++) {
                byte[] left = level[i * 2];
                byte[] right = (i * 2 + 1 < level.length) ? level[i * 2 + 1] : EMPTY_HASH;
                next[i] = hashInternal(left, right);
            }
            level = next;
        }
        return level[0];
    }

    /**
     * Verifies a block's actual transactions hash up to the merkle root
     * the (already header-validated) block header claims.
     */
    public static boolean verify(List<byte[]> txids, byte[] claimedMerkleRoot) {
        if (txids.isEmpty()) {
            return Arrays.equals(claimedMerkleRoot, new byte[32]);
        }
        byte[] computed = buildRoot(txids);
        return Arrays.equals(computed, claimedMerkleRoot);
    }
}