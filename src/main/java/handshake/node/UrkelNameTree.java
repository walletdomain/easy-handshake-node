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

    /** How many commit boundaries to let pass between prunes -- pruning
     *  itself is a pure internal optimization with no real-protocol
     *  requirement to run on the commit schedule, unlike TREE_INTERVAL
     *  itself. Confirmed via direct timing that the walk phase of a
     *  prune (visiting every node reachable from the live tree) costs
     *  roughly the same ~70 seconds regardless of how much has actually
     *  been orphaned since the last prune -- it's driven by the size of
     *  the whole live tree, not by elapsed time. That means running it
     *  less often directly cuts the AVERAGE per-block cost by roughly
     *  this same factor, without meaningfully reintroducing the old
     *  disk-bloat problem (the removal phase is now fast regardless of
     *  batch size, so a larger backlog still clears quickly once pruned).
     *  This is a mitigation, not a fix for the walk's own cost -- the
     *  real fix is tracking orphaned nodes incrementally as updates
     *  happen, avoiding the periodic full-tree walk entirely, which is
     *  a separate, more involved change to insert()/remove() themselves. */
    private static final int PRUNE_EVERY_N_COMMITS = 10;
    private int commitsSinceLastPrune = 0;

    /** A single, dedicated daemon thread for pruning -- see
     *  maybeCommit()'s own comment for the full reasoning. Daemon so it
     *  never blocks a clean shutdown, matching the pattern already used
     *  for every other background thread in this codebase. */
    private final java.util.concurrent.ExecutorService pruneExecutor =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "urkel-prune");
                t.setDaemon(true);
                return t;
            });

    /** Guards against submitting a second prune while one is still
     *  running -- if the walk is still going by the time the next
     *  scheduled prune boundary arrives, that boundary is simply
     *  skipped rather than queued, since the executor's own single
     *  thread would just make it wait anyway; skipping means the
     *  height it would have run at doesn't matter, and the one after
     *  it will try again. */
    private final java.util.concurrent.atomic.AtomicBoolean pruneInProgress =
            new java.util.concurrent.atomic.AtomicBoolean(false);

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
     *  commit actually happened this call.
     *
     *  Also the one safe, natural point to KICK OFF pruning: right
     *  here, committedRootNode and the live root are, for this single
     *  instant, the exact same object graph (committedRootNode was
     *  just set to a snapshot of it on the line above) -- so a
     *  reachability walk from either one captures everything BOTH the
     *  live tree (for continuing forward) and the committed root (for
     *  proveCommitted()/getnameproof) still need, without needing two
     *  separate walks or any risk of the two views having already
     *  diverged.
     *
     *  FIX: previously ran the whole walk+removal INLINE, blocking
     *  this call (and therefore the entire main sync thread, since
     *  this is called from BlockProcessor's per-block path) for however
     *  long the walk took -- confirmed via direct timing to be 66-97
     *  seconds even after every other optimization applied here,
     *  because it's driven by the size of the whole live tree, not by
     *  how much has changed. That cost is real and currently
     *  unavoidable without a substantially riskier rewrite of
     *  insert()/remove() themselves (attempted and reverted earlier --
     *  a rigorous cross-check against this exact walk caught a genuine
     *  data-loss bug in that approach). What CAN be fixed safely,
     *  without touching any of that already-verified tree logic at
     *  all, is WHERE this work runs: committedRootNode is a frozen,
     *  immutable snapshot the instant it's captured (insert()/remove()
     *  never mutate existing nodes, only build new ones), so a
     *  background thread walking it can never be corrupted by the main
     *  thread continuing to mutate the LIVE tree concurrently -- they
     *  operate on different, non-overlapping object graphs by
     *  construction. Submitting the walk+removal to its own thread
     *  here means block processing keeps running at full speed while
     *  pruning catches up quietly in the background, rather than
     *  freezing everything for up to a minute and a half every time it
     *  runs. */
    public boolean maybeCommit(int height) {
        if (height % TREE_INTERVAL != 0) return false;
        lastCommittedRoot = tree.rootHash().clone();
        committedRootNode = tree.snapshotRoot();

        commitsSinceLastPrune++;
        if (commitsSinceLastPrune < PRUNE_EVERY_N_COMMITS) {
            return true; // commit happened; skip pruning this cycle
        }
        commitsSinceLastPrune = 0;

        if (!pruneInProgress.compareAndSet(false, true)) {
            // A previous prune is still running -- skip this boundary
            // entirely rather than queue another one behind it; the
            // next boundary (36 blocks later) will try again, and
            // nothing here depends on pruning happening at any
            // SPECIFIC height, only on it happening often enough.
            System.out.println("[UrkelNameTree] Skipping prune at height " + height
                    + " -- a previous prune is still running in the background");
            return true;
        }

        UrkelNode rootToPrune = committedRootNode;
        // FIX: keySnapshot MUST be captured here, synchronously, at the
        // same instant as rootToPrune above -- NOT inside the async
        // lambda below. See UrkelTree.pruneUnreachableFrom()'s own
        // comment for the full, serious reasoning: the delay between
        // submitting work to the executor and the executor actually
        // starting it is itself a real window during which the main
        // thread keeps persisting new, not-yet-committed nodes. A
        // snapshot taken late (inside the lambda, as this used to do)
        // would wrongly include those newer nodes as removal
        // candidates, since they're on disk by then but not reachable
        // from this (older) committed root -- silently deleting data
        // the live tree still needs. Confirmed as a real, reproducible
        // bug via a direct restart-vs-continuous test before this fix.
        java.util.Set<UrkelNodeStore.HashKey> keySnapshot = tree.snapshotStoreKeys();
        pruneExecutor.submit(() -> {
            // FIX: previously an exception here (confirmed via a real,
            // observed MVStore "Chunk ... not found" error at this
            // exact point) propagated all the way out and caused the
            // ENTIRE block to be treated as an internal-error failure
            // -- but a failed prune doesn't actually threaten
            // correctness here. The committed/live root was already
            // fixed above, computed from the in-memory tree, before
            // this ever runs; pruning is pure disk cleanup, and
            // pruneUnreachable() already computes its full removal
            // list before removing anything, so even a failure mid-
            // removal can only leave extra garbage for the next
            // prune's walk to catch -- it can never remove something
            // still needed. Now running on its own background thread,
            // this isolation matters even more: a failure here must
            // never propagate anywhere near the main sync thread.
            try {
                long pruneStart = System.currentTimeMillis();
                UrkelTree.PruneResult result = tree.pruneUnreachableFrom(rootToPrune, keySnapshot);
                long pruneMillis = System.currentTimeMillis() - pruneStart;
                System.out.printf("[UrkelNameTree] Background prune (started at height %d): "
                                + "removed %d entries in %dms total (walk=%dms remove=%dms)%n",
                        height, result.removed(), pruneMillis, result.walkMillis(), result.removeMillis());
            } catch (Exception e) {
                System.err.printf("[UrkelNameTree] Background prune (started at height %d) "
                        + "failed (non-fatal -- will retry at a later commit boundary): %s%n", height, e);
            } finally {
                pruneInProgress.set(false);
            }
        });

        return true;
    }

    /** Shuts down the background prune executor gracefully -- waits for
     *  any prune currently in flight to actually finish before
     *  returning, rather than letting it continue running against a
     *  store that's about to be closed out from under it. Confirmed as
     *  a real, necessary step: a background prune left running past
     *  ChainDB.close() hit a genuine MVStoreException reading from the
     *  now-closed file, caught safely by the existing non-fatal
     *  handling but exactly the class of shutdown race this project
     *  has already had to fix once before (interrupting a thread mid-
     *  file-I/O). Call this BEFORE closing the underlying store, not
     *  after. */
    public void shutdownPruning() {
        pruneExecutor.shutdown();
        try {
            if (!pruneExecutor.awaitTermination(120, java.util.concurrent.TimeUnit.SECONDS)) {
                System.err.println("[UrkelNameTree] Background prune did not finish within 120s "
                        + "during shutdown -- proceeding anyway, since it's daemon and non-fatal, "
                        + "but this may leave a warning logged from a prune that lost its store.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
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