package handshake.node;

/** Thrown by BlockProcessor when the computed Urkel tree root diverges
 *  from what a block's header claims -- see BlockProcessor.processBlock()'s
 *  own comment for why this is now a hard stop rather than a warn-only
 *  log line. Carries enough for the caller (ChainSync) to decide whether
 *  UrkelTreeRecovery has a plausible basis to attempt self-correction,
 *  without the caller needing to re-derive any of this itself. */
public class UrkelTreeMismatchException extends RuntimeException {
    public final int height;
    public final byte[] claimedRoot;
    public final byte[] computedRoot;
    /** -1 if no deep-catch-up reconciliation has ever deleted anything
     *  in this run -- see UrkelNameTree.firstDeepCatchUpDeletionHeight()'s
     *  own comment for the full reasoning on why this is the relevant
     *  question, not just "did a mismatch happen." */
    public final int firstDeepCatchUpDeletionHeight;

    public UrkelTreeMismatchException(int height, byte[] claimedRoot, byte[] computedRoot,
                                      int firstDeepCatchUpDeletionHeight) {
        super("Urkel tree root mismatch at height " + height);
        this.height = height;
        this.claimedRoot = claimedRoot;
        this.computedRoot = computedRoot;
        this.firstDeepCatchUpDeletionHeight = firstDeepCatchUpDeletionHeight;
    }
}