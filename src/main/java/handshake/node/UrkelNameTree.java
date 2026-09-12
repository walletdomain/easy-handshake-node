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

    /** FIX (superseded): this project used to also reduce reconciliation
     *  frequency during deep catch-up via a second, larger commit-count
     *  interval here -- removed entirely once the validation walk was
     *  removed from this path too (see MAX_CANDIDATES_BEFORE_RECONCILIATION's
     *  own comment for the real incident that prompted the replacement).
     *  A commit-count interval was the right kind of trigger for
     *  bounding walk-frequency-cost; once there's no walk left to
     *  protect against, a fixed commit window can't bound the thing
     *  that actually matters anymore -- candidate volume, which varies
     *  with chain density (confirmed up to 20x across different
     *  ranges) independent of how many commits have passed. Replaced
     *  with a memory-proportional candidate-count threshold instead. */
    private int commitsSinceLastPrune = 0;

    /** RE-ARCHITECTURE: accumulates advanceOrphanGeneration()'s output
     *  across EVERY commit, not just reconciliation ones -- candidates
     *  pile up here for however many commits pass between actual
     *  reconciliation runs (matching the existing reduced-during-
     *  catchup cadence), then get validated against a real walk and
     *  cleared as one batch. See maybeCommit()'s own comment for the
     *  full reasoning on why this hybrid exists at all. */
    private final java.util.Set<UrkelNodeStore.HashKey> accumulatedOrphanCandidates =
            java.util.Collections.newSetFromMap(new java.util.concurrent.ConcurrentHashMap<>());

    /** Formats current JVM heap usage for diagnostic logging -- used
     *  and maxMemory (the -Xmx ceiling), not free/total (which reflect
     *  the JVM's CURRENT allocated heap size, not its actual ceiling,
     *  and can be misleading on their own). A live reading, not
     *  preceded by a forced GC -- deliberately, since calling
     *  System.gc() from inside routine diagnostic logging would itself
     *  be a real performance cost on a hot path; this trades some
     *  precision (may include garbage not yet collected) for being
     *  genuinely free to call anywhere, including per-block. Added
     *  specifically because a real, reported crash could only be
     *  diagnosed after the fact, by inference from height alignment
     *  and external tooling (the IDE's own profiler) -- this makes the
     *  console itself the source of truth for what memory was actually
     *  doing at any given moment, not something to reconstruct later. */
    static String heapSnapshot() {
        Runtime rt = Runtime.getRuntime();
        long used = (rt.totalMemory() - rt.freeMemory()) / 1_048_576;
        long max = rt.maxMemory() / 1_048_576;
        return used + "MB/" + max + "MB";
    }

    /** RE-ARCHITECTURE: dynamically bounds how many candidates the
     *  deep-catch-up (no-validation-walk) reconciliation path
     *  accumulates before triggering, scaled by actual detected system
     *  memory -- same detection pattern already used for the RocksDB
     *  block cache (see RocksDBKVStore.detectSharedBlockCacheBytes()'s
     *  own comment), applied to a different, newer problem.
     *
     *  This path removed the validation walk entirely for speed during
     *  catch-up, which also removed the walk's own natural ceiling on
     *  how much memory a single reconciliation cycle could need. What's
     *  left scaling peak memory is purely candidate VOLUME -- and that
     *  was previously bounded only by a fixed commit-count interval
     *  (originally tuned for a completely different cost, the walk's
     *  own time, which no longer applies on this path at all). During
     *  a genuine high-density stretch of the chain -- confirmed,
     *  repeatedly, to vary by as much as 20x across different ranges --
     *  a fixed commit-count window just accumulates a proportionally
     *  larger batch: a real production run hit 7.68 million candidates
     *  in one cycle, pushing heap to 4.9GB. Comfortably recoverable on
     *  an 8GB machine (confirmed: the very next cycle settled under
     *  700MB); on a 4GB machine, after OS and RocksDB's own native
     *  overhead, a peak anywhere near that would very plausibly not
     *  survive.
     *
     *  Bytes-per-candidate here (670) is the REAL, observed production
     *  ratio from that exact incident (4.9GB / 7.68M), not a clean-room
     *  estimate -- a direct, isolated measurement of just the
     *  HashSet-plus-removal-list came out to roughly a third of that
     *  (223 bytes/candidate), with the gap almost certainly coming from
     *  RocksDB's own native WriteBatch memory for millions of
     *  individual deletes, plus concurrent main-thread activity,
     *  neither of which an isolated JVM-heap-only measurement can see.
     *  Designing around the real, observed number, not the
     *  optimistic one, given how many "should be fine" assumptions this
     *  project has already had to walk back this session.
     *
     *  Floor and ceiling exist for the same reasons as the block
     *  cache's own: a floor so even a genuinely tiny machine doesn't
     *  reconcile so often that fixed per-cycle overhead starts to
     *  dominate; a ceiling so a very large, dedicated machine doesn't
     *  let an unbounded amount of candidates -- and therefore risk --
     *  accumulate between cycles just because it technically has the
     *  RAM to hold them. */
    private static final long CANDIDATE_MEMORY_BUDGET_FRACTION_BYTES_PER_CANDIDATE = 670;

    private static int detectMaxCandidatesBeforeReconciliation() {
        long floor = 150_000;
        long ceiling = 3_000_000;
        try {
            var osBean = (com.sun.management.OperatingSystemMXBean)
                    java.lang.management.ManagementFactory.getOperatingSystemMXBean();
            long totalPhysical = osBean.getTotalMemorySize();
            long budgetBytes = totalPhysical / 20; // 5% of total system memory
            long maxCandidates = budgetBytes / CANDIDATE_MEMORY_BUDGET_FRACTION_BYTES_PER_CANDIDATE;
            return (int) Math.max(floor, Math.min(maxCandidates, ceiling));
        } catch (Exception | LinkageError e) {
            System.out.println("[UrkelNameTree] Could not detect physical memory ("
                    + e.getClass().getSimpleName() + ") -- using a conservative 300,000-candidate default.");
            return 300_000;
        }
    }

    private static final int MAX_CANDIDATES_BEFORE_RECONCILIATION = detectMaxCandidatesBeforeReconciliation();


    /** A single, dedicated daemon thread for pruning -- see
     *  maybeCommit()'s own comment for the full reasoning. Daemon so it
     *  never blocks a clean shutdown, matching the pattern already used
     *  for every other background thread in this codebase. */
    private final java.util.concurrent.ExecutorService pruneExecutor =
            java.util.concurrent.Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "urkel-prune");
                t.setDaemon(true);
                // FIX: confirmed via a real, reported case -- an entire
                // machine becoming unusable, not just this process --
                // during a prune's walk at real production scale
                // (millions of live names, an order of magnitude past
                // anything tested here beforehand). Thread priority is
                // only ever a hint to the OS scheduler, not a
                // guarantee, and its exact effect is platform-dependent
                // -- but on Windows specifically (confirmed as the
                // platform actually in use) it does map to a real,
                // observable OS-level scheduling class, so this should
                // give the OS a genuine, if imperfect, reason to favor
                // the user's own foreground work over this background
                // cleanup whenever they're actually competing for the
                // same CPU. Combined with collectReachable()'s own
                // periodic yielding (see its comment), not a complete
                // fix by itself.
                t.setPriority(Thread.MIN_PRIORITY);
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

    /** Constructs the right kind of node reference for lastCommittedRoot
     *  -- Null.NIL specifically for "nothing committed yet" (a
     *  genuinely fresh database), NOT a Hash placeholder wrapping the
     *  zero value: Null.hash() and an empty tree's hash are the SAME
     *  all-zero value by construction, but resolve() treats them very
     *  differently -- Null.isNull() short-circuits immediately
     *  ("nothing to read for an empty subtree"), while a real Hash
     *  placeholder triggers an actual on-disk lookup for a node that,
     *  for a genuinely empty tree, was never written and doesn't
     *  exist. Getting this backwards would throw "missing node" on
     *  the very first commit of a fresh sync. Cheap to call every time
     *  rather than cache -- this is exactly the point of this whole
     *  change: nothing here is meant to be a standing, retained object
     *  graph anymore, just a hash value materialized into a lightweight
     *  reference only for as long as a specific call actually needs one. */
    private UrkelNode committedRootAsNode() {
        return java.util.Arrays.equals(lastCommittedRoot, UrkelHash.ZERO)
                ? UrkelNode.Null.NIL
                : new UrkelNode.Hash(lastCommittedRoot);
    }

    public UrkelNameTree() {}

    /** Resumes from persisted state -- liveRootHash/committedRootHash
     *  as read from ChainDB's own meta storage (all-zero means "never
     *  persisted before", i.e. a genuinely fresh database, in which
     *  case the tree just starts empty as normal). The live root gets
     *  injected as a lazy Hash placeholder, resolved from nodeStore on
     *  demand as queries actually need it -- nothing is eagerly
     *  loaded. The committed root is just the hash value itself; see
     *  committedRootAsNode() for how (and why) that gets turned into a
     *  node reference only at the point something actually needs one. */
    public UrkelNameTree(UrkelNodeStore nodeStore, byte[] liveRootHash, byte[] committedRootHash) {
        tree.setNodeStore(nodeStore);

        if (liveRootHash != null && !java.util.Arrays.equals(liveRootHash, UrkelHash.ZERO)) {
            tree.inject(new UrkelNode.Hash(liveRootHash));
        }

        if (committedRootHash != null && !java.util.Arrays.equals(committedRootHash, UrkelHash.ZERO)) {
            lastCommittedRoot = committedRootHash.clone();
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
        return tree.proveFrom(committedRootAsNode(), nameHash);
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
     *  bestKnownPeerHeight: same value, same meaning, as
     *  BlockProcessor's own signature-verification-skip parameter --
     *  0 means unknown (treated safely as "assume we're at/near the
     *  tip"), otherwise the highest height a connected peer has
     *  reported. Used here to decide which reconciliation strategy
     *  applies -- see MAX_CANDIDATES_BEFORE_RECONCILIATION's own
     *  comment for the deep-catch-up path's full reasoning.
     *
     *  Also the one safe, natural point to KICK OFF reconciliation.
     *
     *  RE-ARCHITECTURE (both steps now complete): this class used to
     *  also keep a standing, retained object-graph reference
     *  (committedRootNode) alongside lastCommittedRoot's own hash value.
     *  That field is gone -- nothing here holds a live object graph
     *  across blocks anymore, only the 32-byte hash itself
     *  (committedRootAsNode() constructs a fresh, lightweight reference
     *  only at the point something actually needs one). UrkelTree's own
     *  live root got the same treatment next (see its persistLive()).
     *  Confirmed as a real, necessary change, not a style preference --
     *  a real, reported OutOfMemoryError crash, landing consistently in
     *  the same high-activity height range even after a first attempt
     *  at fixing this (collapsing already-persisted nodes back to
     *  lightweight placeholders, which measurably cut memory ~12.6x but
     *  still wasn't enough under sustained, extreme load). Both
     *  standing references are gone now -- what followed from there was
     *  a longer chain of fixes for a different, smaller problem: the
     *  walk itself scaling with total tree size, addressed first by
     *  incremental orphan tracking (see UrkelTree's own comments), then
     *  by removing the walk from the deep-catch-up path entirely (see
     *  MAX_CANDIDATES_BEFORE_RECONCILIATION), then by disk-backing the
     *  walk that remains near the tip (see DiskBackedHashKeySet). */
    public boolean maybeCommit(int height, int bestKnownPeerHeight) {
        if (height % TREE_INTERVAL != 0) return false;
        lastCommittedRoot = tree.rootHash().clone();

        // RE-ARCHITECTURE: accumulate this window's orphan candidates
        // EVERY commit, regardless of whether this specific commit also
        // triggers reconciliation -- essentially free (the tracking
        // already happened during insert()/remove(); this just collects
        // it), and means nothing is lost if several commits pass before
        // the next reconciliation actually runs.
        accumulatedOrphanCandidates.addAll(tree.advanceOrphanGeneration());

        // Same threshold, same reasoning, as BlockProcessor's own
        // signature-verification skip -- see
        // BlockProcessor.SIGNATURE_VERIFICATION_DEPTH's own comment for
        // why reusing that exact constant, rather than a second,
        // separately chosen number, matters here.
        boolean deepCatchUp = bestKnownPeerHeight > 0
                && (bestKnownPeerHeight - height) > BlockProcessor.SIGNATURE_VERIFICATION_DEPTH;

        // RE-ARCHITECTURE: the two paths now trigger on genuinely
        // different things, not the same commit-count schedule with a
        // different number plugged in. Near the tip, the real cost is
        // the (now disk-backed, but still real) validation walk's own
        // time -- a commit-count interval is the right kind of trigger
        // for that, same as before. During deep catch-up, there's no
        // walk at all anymore, so there's nothing left for a commit-
        // count interval to actually be protecting against; the real
        // cost driver is candidate VOLUME, which a fixed commit window
        // can't bound on its own once chain density varies as much as
        // this one's confirmed to (up to 20x between ranges) -- see
        // detectMaxCandidatesBeforeReconciliation()'s own comment for
        // the full reasoning and the real incident that prompted this.
        boolean shouldReconcile;
        if (deepCatchUp) {
            shouldReconcile = accumulatedOrphanCandidates.size() >= MAX_CANDIDATES_BEFORE_RECONCILIATION;
        } else {
            commitsSinceLastPrune++;
            shouldReconcile = commitsSinceLastPrune >= PRUNE_EVERY_N_COMMITS;
        }
        if (!shouldReconcile) {
            return true; // commit happened; skip reconciliation this cycle
        }
        commitsSinceLastPrune = 0;

        if (!pruneInProgress.compareAndSet(false, true)) {
            // A previous reconciliation is still running -- skip this
            // boundary entirely rather than queue another one behind
            // it; the next boundary (36 blocks later) will try again,
            // and nothing here depends on it happening at any SPECIFIC
            // height, only on it happening often enough. Candidates
            // keep accumulating above regardless -- nothing is lost by
            // skipping, only deferred.
            System.out.println("[UrkelNameTree] Skipping reconciliation at height " + height
                    + " -- a previous one is still running in the background");
            return true;
        }

        System.out.println("[UrkelNameTree] Reconciliation STARTING at height " + height
                + " (heap: " + heapSnapshot() + ", " + accumulatedOrphanCandidates.size() + " candidates, "
                + (deepCatchUp ? "trusting candidates directly, no validation walk -- deep catch-up"
                : "full disk-backed validation walk -- near the tip"));

        // Constructed fresh, right here, right now -- NOT retained
        // anywhere else, and NOT reused from a field that would
        // otherwise sit around for the entire next 36-block window.
        // See this method's own comment above for why that distinction
        // is the actual point of this change, not incidental to it.
        UrkelNode rootToPrune = committedRootAsNode();

        // RE-ARCHITECTURE: synchronous copy-and-clear, at this exact
        // instant, for the SAME reason rootToPrune above must be
        // captured here and not inside the async lambda below -- the
        // scheduling delay between submitting work and the executor
        // actually starting it is a real window during which the main
        // thread keeps accumulating MORE candidates from later blocks.
        // Copying here is cheap: pure in-memory reference copying, not
        // a disk read or a tree walk, so doing it synchronously doesn't
        // reintroduce the blocking cost that made the OLD full key
        // enumeration a real problem.
        java.util.Set<UrkelNodeStore.HashKey> candidatesSnapshot =
                new java.util.HashSet<>(accumulatedOrphanCandidates);
        accumulatedOrphanCandidates.clear();

        pruneExecutor.submit(() -> {
            // FIX: previously an exception here (confirmed via a real,
            // observed MVStore "Chunk ... not found" error at this
            // exact point) propagated all the way out and caused the
            // ENTIRE block to be treated as an internal-error failure
            // -- but a failed reconciliation doesn't actually threaten
            // correctness here. The committed/live root was already
            // fixed above, computed from the in-memory tree, before
            // this ever runs; this is pure disk cleanup, and both
            // reconcileAndRemove() and removeDirectly() only ever
            // remove exactly what they already, explicitly decided to,
            // so even a failure mid-removal can only leave extra
            // garbage for the next reconciliation to catch -- it can
            // never remove something still needed. A failure here must
            // never propagate anywhere near the main sync thread.
            try {
                long start = System.currentTimeMillis();
                if (deepCatchUp) {
                    // RE-ARCHITECTURE: no walk at all during deep catch-
                    // up -- see UrkelTree.removeDirectly()'s own comment
                    // for the full reasoning on this trade-off.
                    int removed = tree.removeDirectly(candidatesSnapshot);
                    long millis = System.currentTimeMillis() - start;
                    System.out.printf("[UrkelNameTree] Reconciliation (started at height %d): "
                                    + "removed %d of %d candidates in %dms (no validation walk -- catch-up)%n",
                            height, removed, candidatesSnapshot.size(), millis);
                } else {
                    UrkelTree.PruneResult result = tree.reconcileAndRemove(rootToPrune, candidatesSnapshot);
                    long millis = System.currentTimeMillis() - start;
                    System.out.printf("[UrkelNameTree] Reconciliation (started at height %d): "
                                    + "removed %d of %d candidates in %dms total (walk=%dms remove=%dms)%n",
                            height, result.removed(), candidatesSnapshot.size(), millis,
                            result.walkMillis(), result.removeMillis());
                }
            } catch (UrkelTree.PruneInterruptedException e) {
                // Expected, clean abort during shutdown -- see
                // collectReachable()'s and shutdownPruning()'s own
                // comments. Not a failure; the process is on its way
                // down regardless, but still re-queue -- if this
                // reconciliation gets to run to completion on some
                // future startup instead (e.g. interrupted then
                // resumed without ever reaching this exact commit
                // boundary again), these candidates should still be
                // considered rather than silently lost. Harmless if
                // the process really is about to exit either way.
                accumulatedOrphanCandidates.addAll(candidatesSnapshot);
                System.out.println("[UrkelNameTree] Reconciliation (started at height " + height
                        + ") stopped early: shutdown requested.");
            } catch (Exception e) {
                // FIX: on failure, put this batch's candidates back for
                // the NEXT reconciliation to retry -- without this, a
                // failure here would silently and permanently lose
                // track of real garbage (it stays correctly unreachable
                // and correctly still on disk, just with nothing left
                // that would ever schedule it for cleanup again, since
                // there's no more automatic full-store scan as a
                // backstop). Safe to do from this background thread
                // because accumulatedOrphanCandidates is a concurrent
                // set specifically for this -- the main thread keeps
                // adding to it via maybeCommit() the whole time this
                // task runs.
                accumulatedOrphanCandidates.addAll(candidatesSnapshot);
                System.err.printf("[UrkelNameTree] Reconciliation (started at height %d) "
                        + "failed (non-fatal -- candidates re-queued for the next attempt): %s%n", height, e);
            } finally {
                pruneInProgress.set(false);
            }
        });

        return true;
    }

    /** Shuts down the background prune executor gracefully -- waits,
     *  UNCONDITIONALLY, for any prune currently in flight to actually
     *  finish before returning, rather than letting it continue running
     *  against a store that's about to be closed out from under it.
     *  Call this BEFORE closing the underlying store, not after.
     *
     *  FIX: this used to give up after a 120s timeout and proceed
     *  anyway, reasoning (from when this ran under MVStore) that a
     *  prune still running past this point would hit a catchable,
     *  already-safely-handled MVStoreException -- non-fatal. That
     *  reasoning does NOT carry over to RocksDB: it's native code
     *  reached via JNI, and a still-running prune making a call into it
     *  after store.close() has already freed the underlying native
     *  handle is a genuine use-after-free at the native level, which
     *  segfaults the entire process rather than throwing anything
     *  catchable -- confirmed directly, via a real crash with exactly
     *  this shape (this timeout's own warning printed, immediately
     *  followed by the JVM dying with a native access-violation exit
     *  code). "Proceed anyway" was never actually safe once this
     *  project moved off MVStore; it simply hadn't been exercised
     *  under real, sustained load long enough for a prune to still be
     *  running 120s into a shutdown until now.
     *
     *  Fixed at the root, not by raising the timeout (which only
     *  narrows the window, and this project's own recent choice to
     *  reduce prune frequency during catch-up directly makes individual
     *  prunes take LONGER when they do run, not shorter -- a larger
     *  timeout would still eventually be crossed): pruneExecutor.shutdownNow()
     *  actually interrupts whatever's running, and collectReachable()
     *  (the walk phase, confirmed as where a real prune spends nearly
     *  all its time) now checks for that interrupt on every node
     *  visited, aborting cleanly and quickly rather than running to
     *  completion regardless. Combined with an unconditional wait here
     *  -- looped, with periodic progress logging rather than either a
     *  silent, indefinite block or a timeout that gives up -- shutdown
     *  is fast in the ordinary case (the walk notices the interrupt
     *  almost immediately) AND never unsafe in the worst case (if
     *  something ever did take unexpectedly long, this simply keeps
     *  waiting rather than risking the crash). */
    public void shutdownPruning() {
        pruneExecutor.shutdownNow();
        try {
            int waitedSeconds = 0;
            while (!pruneExecutor.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS)) {
                waitedSeconds += 10;
                System.out.println("[UrkelNameTree] Still waiting for the background prune to stop "
                        + "(" + waitedSeconds + "s so far) -- this must finish before the database "
                        + "can be safely closed, so shutdown will keep waiting rather than risk a crash.");
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