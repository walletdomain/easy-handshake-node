package handshake.node;

/**
 * Manages the persistent Urkel tree of name states across blocks,
 * including the real 36-block commit interval confirmed directly from
 * chaindb.js: every block, touched names get inserted/removed into an
 * ongoing tree (chaindb.js's "await this.txn.insert(nameHash,
 * ns.encode())" / "await this.txn.remove(nameHash)"), but the
 * "official" root that block headers actually commit to only advances
 * every treeInterval (36) blocks -- confirmed from chain.js's
 * "(entry.height % this.network.names.treeInterval) === 0".
 *
 * Persists to disk (via UrkelNodeStore/UrkelTree's own resolver
 * support) after EVERY block, not just at commit boundaries -- this
 * project's block-tip tracking means a restart never replays
 * already-processed blocks, so if only the last committed snapshot
 * were durable, any blocks processed between the last commit and a
 * restart would have their tree changes permanently lost (they'd
 * never be reprocessed to regenerate them), and the next commit would
 * compute a genuinely wrong root. Tracking a separate live-root
 * pointer (persisted every block) alongside the committed-root pointer
 * (persisted only every interval) is what keeps both correct across a
 * restart at any point, not just at a clean interval boundary.
 */
public class UrkelNameTree {

    /** Confirmed directly from chain.js/chaindb.js: names.treeInterval
     *  on mainnet is 36 blocks (~6 hours). */
    public static final int TREE_INTERVAL = 36;

    private final UrkelTree tree = new UrkelTree(256);
    private byte[] lastCommittedRoot = UrkelHash.ZERO.clone();
    private UrkelNode committedRootNode = UrkelNode.Null.NIL;

    public UrkelNameTree() {}

    /** Resumes from persisted state -- liveRootHash/committedRootHash
     *  as read from ChainDB's own meta storage (all-zero means "never
     *  persisted before", i.e. a genuinely fresh database, in which
     *  case the tree just starts empty as normal). Both get injected
     *  as lazy Hash placeholders, resolved from nodeStore on demand as
     *  queries actually need them -- nothing is eagerly loaded. */
    public UrkelNameTree(UrkelNodeStore nodeStore, byte[] liveRootHash, byte[] committedRootHash) {
        tree.setNodeStore(nodeStore);

        if (liveRootHash != null && !java.util.Arrays.equals(liveRootHash, UrkelHash.ZERO)) {
            tree.inject(new UrkelNode.Hash(liveRootHash));
        }

        if (committedRootHash != null && !java.util.Arrays.equals(committedRootHash, UrkelHash.ZERO)) {
            lastCommittedRoot = committedRootHash.clone();
            committedRootNode = new UrkelNode.Hash(committedRootHash);
        }
    }

    /** The root value that should actually be compared against a block
     *  header's treeRoot field -- NOT tree.rootHash(), which reflects
     *  every pending change immediately rather than only at commit
     *  boundaries. */
    public byte[] committedRoot() {
        return lastCommittedRoot;
    }

    /** The tree's current live root -- changes with every block that
     *  touches any name, persisted every block (see persistBlock())
     *  specifically so this remains recoverable across a restart at
     *  any point, not just at a commit boundary. */
    public byte[] liveRoot() {
        return tree.rootHash();
    }

    /** Builds a proof for a name against the last COMMITTED root, not
     *  the tree's live state -- this is the proof that's actually
     *  verifiable against a real, already-mined block header, matching
     *  real hsd's own getnameproof (which proves against
     *  "this.chain.tip.treeRoot", not a live, uncommitted tree). A
     *  name changed since the last commit boundary won't be reflected
     *  here yet -- that's correct, not a bug, since a proof of it
     *  wouldn't verify against any real header either. */
    public UrkelProof proveCommitted(byte[] nameHash) {
        return tree.proveFrom(committedRootNode, nameHash);
    }

    /** Applies one name's new state for the block currently being
     *  processed -- called once per touched name, per block, mirroring
     *  chaindb.js's per-block loop over view.names.values(). Does NOT
     *  by itself change committedRoot(); that only happens via
     *  maybeCommit() at an actual interval boundary. */
    public void applyNameState(byte[] nameHash, UrkelNameState state) {
        if (state.isNull()) {
            tree.remove(nameHash);
        } else {
            tree.insert(nameHash, state.encode());
        }
    }

    /** Call once per block, after all of that block's covenant outputs
     *  have been applied via applyNameState() -- writes any newly
     *  created nodes to disk (a no-op walk if this block touched no
     *  names, since there'd be nothing new to persist). This is what
     *  makes the live root recoverable after a restart at any point,
     *  not just at a commit boundary. */
    public void persistBlock() {
        tree.persistLive();
    }

    /** Call once per block, after persistBlock(). If this block's
     *  height lands on a real interval boundary, this is the point
     *  where the tree's current (live) root becomes the new "official"
     *  committed root -- matching chaindb.js's "await
     *  this.txn.commit()" at the same boundary. Returns true if a
     *  commit actually happened this call. */
    public boolean maybeCommit(int height) {
        if (height % TREE_INTERVAL != 0) return false;
        lastCommittedRoot = tree.rootHash().clone();
        committedRootNode = tree.snapshotRoot();
        return true;
    }

    /** Looks up a name's current state directly (bypassing the
     *  interval-commit distinction -- this reflects live, not-yet-
     *  officially-committed state, useful for RPC lookups that want
     *  the real current value rather than what's provable against the
     *  last committed header). Returns null if the name has no
     *  current tree entry. */
    public UrkelNameState get(byte[] nameHash) {
        byte[] raw = tree.get(nameHash);
        return raw == null ? null : UrkelNameState.decode(raw);
    }

    /** Builds a proof for a name against the tree's current LIVE root
     *  (not necessarily the last committed one) -- callers that need a
     *  proof verifiable against a specific historical header should
     *  use proveCommitted() instead; this exposes the tree's current
     *  proving capability directly. */
    public UrkelProof prove(byte[] nameHash) {
        return tree.prove(nameHash);
    }
}