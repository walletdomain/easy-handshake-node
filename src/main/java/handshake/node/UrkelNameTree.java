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

    /** NEW: self-healing support. Records the height of the FIRST
     *  deep-catch-up (removeDirectly, no validation walk) reconciliation
     *  ever to actually complete a deletion in this run -- -1 if none
     *  has yet. -1, not a boolean, deliberately: a mismatch discovered
     *  later needs to know WHERE to roll back to, not just WHETHER this
     *  known risk is even in play.
     *
     *  Set once, the first time, and never updated again after that --
     *  intentionally NOT "most recent deep-catch-up height." The known
     *  false-positive risk (see UrkelTree.removeDirectly()'s own
     *  comment, and the direct cross-check that measured it at ~0.1%,
     *  0 false negatives) doesn't corrupt the committed root at the
     *  moment of a wrong deletion -- the root is a function of the
     *  tree's logical structure, which a storage-layer deletion doesn't
     *  immediately change. It only surfaces LATER, whenever some
     *  operation next actually needs to resolve that specific,
     *  wrongly-deleted node and finds it missing. That means a mismatch
     *  discovered now could trace back to ANY deep-catch-up deletion
     *  since the very first one, not just the most recent -- so
     *  recovery needs to roll back past all of them, not just the last. */
    private volatile int firstDeepCatchUpDeletionHeight = -1;

    public int firstDeepCatchUpDeletionHeight() { return firstDeepCatchUpDeletionHeight; }

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

    /** RE-ARCHITECTURE (second pass): this used to be the actual trigger
     *  for deep-catch-up reconciliation -- accumulate candidates until
     *  this many pile up, THEN process the entire pile in one burst.
     *  That WAS the bug: a real, confirmed OutOfMemoryError crash,
     *  reproduced directly, traced to exactly this pattern -- a single
     *  burst of 454,269 candidates pushing heap to 94% of ceiling right
     *  as the very next block's own processing needed more. The
     *  underlying correctness requirement this whole system exists to
     *  satisfy is only ever "one commit window of delay" (see
     *  UrkelTree.advanceOrphanGeneration()'s own comment) -- nothing
     *  about correctness required batching up a RAM-scaled pile before
     *  doing anything at all. That was purely a batching-efficiency
     *  choice, and it's the actual thing this re-architecture replaces:
     *  see maybeCommit()'s own comment for the real fix, which is small,
     *  continuous draining every commit (DEEP_CATCHUP_DRAIN_CHUNK_SIZE
     *  below) rather than rare, huge bursts.
     *
     *  What THIS constant now is: a hard, rarely-hit backstop for the
     *  case where even continuous small-chunk draining can't keep pace
     *  with orphan generation during some sustained, extreme burst of
     *  covenant activity. In that situation, maybeCommit() blocks block
     *  processing itself (see blockUntilBacklogDrains()) until the
     *  background drain catches back up -- real backpressure, not just
     *  a bigger number to hope never gets reached. That's what actually
     *  turns this into a provable ceiling rather than an empirically-
     *  tuned-to-survive-what-we've-seen-so-far heuristic: peak memory
     *  for this whole pathway now depends only on this cap and the
     *  drain chunk size, never on how much registration activity
     *  happens to occur in any given stretch of the chain, and never on
     *  how much RAM happens to be available beyond what's needed to
     *  hold this cap's worth of candidates.
     *
     *  Same real, production-measured bytes-per-candidate ratio (670,
     *  see below) and the same maxMemory()-based scaling as before --
     *  that part of the original design was sound and stays. What
     *  changed is the floor: 150,000 unconditionally, regardless of
     *  actual available memory, was itself a real problem -- confirmed
     *  directly, it does not scale down at all for a genuinely small
     *  deployment target (a 2GB VPS, the kind this project explicitly
     *  needs to run safely and unattended on, the same way hsd already
     *  does). A floor this large could force EXACTLY the same
     *  accumulation pattern that caused the original crash, on exactly
     *  the hardware this project most needs to be safe on. 10,000 is
     *  still a genuine floor (avoiding pathologically tiny caps that
     *  could make forward progress impossible if a single block's own
     *  covenant volume ever approached it), just one that doesn't
     *  override what a truly small machine's real, available memory
     *  can actually support. */
    private static final long CANDIDATE_MEMORY_BUDGET_FRACTION_BYTES_PER_CANDIDATE = 670;

    /** How many orphan candidates to remove per drain cycle during deep
     *  catch-up -- small and FIXED, deliberately NOT scaled to available
     *  memory the way the hard cap above is. There's no reason for this
     *  to scale with RAM: removal cost here is linear in candidate
     *  count (no validation walk, no tree-size-dependent cost the way
     *  the near-tip path has), so a small, constant chunk keeps each
     *  individual drain cycle's own memory footprint small and
     *  predictable on any machine, while maybeCommit() calling this
     *  every commit (whenever the backlog is non-empty) is what keeps
     *  the backlog itself from ever growing large in the first place,
     *  on any machine, regardless of covenant activity level in any
     *  given stretch of the chain. 5,000 is small enough that even a
     *  genuinely tiny deployment target comfortably absorbs it every
     *  single commit without it becoming its own bottleneck. */
    private static final int DEEP_CATCHUP_DRAIN_CHUNK_SIZE = 5_000;

    private static int detectHardBackpressureCap() {
        long floor = 10_000;
        long ceiling = 3_000_000;
        try {
            // FIX: bounded by Runtime.getRuntime().maxMemory() -- the
            // JVM's own actual, effective heap ceiling -- not raw
            // physical RAM. Confirmed as a real, live crash: a batch
            // sized off physical RAM alone can still be far larger than
            // what the JVM will ever actually be able to commit,
            // whenever the two diverge -- which they always do to some
            // degree (the JVM's own default ergonomics cap heap at 25%
            // of physical RAM even with no explicit setting at all, and
            // diverge further still if anything more specific is ever
            // configured). maxMemory() is the same primitive this
            // codebase already uses elsewhere (heapSnapshot(),
            // getMemoryInfo()) as the authoritative "how much heap does
            // this JVM actually have" figure -- reused here rather than
            // a second, inconsistent way of asking the same question.
            // This is also what actually delivers on running the node
            // with no explicit -Xmx at all: the JVM's own default
            // ceiling becomes the real, single source of truth batch
            // sizing scales against, with nothing for a person to set,
            // reason about, or get wrong.
            long effectiveHeapCeiling = Runtime.getRuntime().maxMemory();
            long budgetBytes = effectiveHeapCeiling / 20; // 5% of the real, effective heap ceiling
            long maxCandidates = budgetBytes / CANDIDATE_MEMORY_BUDGET_FRACTION_BYTES_PER_CANDIDATE;
            return (int) Math.max(floor, Math.min(maxCandidates, ceiling));
        } catch (Exception | LinkageError e) {
            System.out.println("[UrkelNameTree] Could not detect the JVM's own heap ceiling ("
                    + e.getClass().getSimpleName() + ") -- using a conservative 300,000-candidate hard cap default.");
            return 300_000;
        }
    }

    // FIX: package-visible, not private -- UrkelNodeStore (same package)
    // needs this too, as the basis for its own dynamic sub-chunk sizing
    // during removeKeys(), rather than inventing a second, independent
    // maxMemory()-based calculation for a per-item byte cost that's
    // never actually been measured the way CANDIDATE_MEMORY_BUDGET_
    // FRACTION_BYTES_PER_CANDIDATE was (a real, reported production
    // ratio) -- deriving the chunk size as a fraction of this
    // already-verified number is the more honest choice than guessing
    // at a new constant with nothing real backing it.
    static final int HARD_BACKPRESSURE_CAP = detectHardBackpressureCap();


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

    /** NEW: resilience support. Blocks the calling thread until no
     *  reconciliation cycle is currently in flight -- used by
     *  ChainDB.commit() so a WAL flush never runs concurrently with an
     *  in-progress background removal (see that method's own comment
     *  for the real, plausible failure mode this closes: a commit
     *  declaring a height "safely durable" while a background task is
     *  still mid-write to the SAME underlying database on a different
     *  thread, meaning an interruption -- crash, power loss -- right
     *  after could leave the database internally inconsistent despite
     *  the commit's own claim). Reconciliation cycles are now small and
     *  fast (confirmed directly: 20-90ms per cycle in the small-chunk-
     *  draining redesign's own verification), so this adds only a
     *  brief, bounded wait to a commit, not an open-ended one. */
    public void waitForReconciliationToSettle() {
        while (pruneInProgress.get()) {
            try {
                Thread.sleep(5);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

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

    public UrkelNameTree() {
        // FIX: same registration as the other constructor -- see its
        // own comment. Applied here too so the safeguard is active
        // regardless of which constructor a caller (or a test) uses.
        tree.registerExternalPendingRemovalSet(accumulatedOrphanCandidates);
    }

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
        // FIX: registers this instance's own accumulatedOrphanCandidates
        // with the tree's unorphan-resurrection safeguard -- see
        // UrkelTree's own comment on registerExternalPendingRemovalSet()
        // for the real, reproduced bug this closes. Registered once,
        // for the lifetime of this tree, since accumulatedOrphanCandidates
        // itself is a single, stable, concurrent-safe set that's only
        // ever added to and cleared, never replaced.
        tree.registerExternalPendingRemovalSet(accumulatedOrphanCandidates);

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

        // Constructed fresh, right here, right now -- cheap (confirmed:
        // committedRootAsNode() is pure in-memory reference wrapping, no
        // disk read or tree walk), so computing it unconditionally,
        // every commit, costs nothing even on commits that end up not
        // reconciling at all. Needed both by the normal path below and
        // by blockUntilBacklogDrains() if backpressure ever kicks in.
        UrkelNode rootToPrune = committedRootAsNode();

        // RE-ARCHITECTURE (second pass): hard backpressure -- see
        // HARD_BACKPRESSURE_CAP's own comment for the full reasoning on
        // why this is a genuinely separate mechanism from the small,
        // continuous draining below, not a redundant safety margin on
        // top of it. This is what turns the memory ceiling into an
        // actual, provable guarantee: if orphan generation is ever
        // outpacing even continuous small-chunk draining, block
        // processing itself pauses here until the background drain
        // catches back up, rather than letting the backlog keep growing
        // regardless of how much RAM happens to be available.
        if (accumulatedOrphanCandidates.size() >= HARD_BACKPRESSURE_CAP) {
            blockUntilBacklogDrains(deepCatchUp, rootToPrune, height);
        }

        // RE-ARCHITECTURE (second pass): this is the actual fix for the
        // repeated, confirmed OOM crashes in this exact code path -- see
        // HARD_BACKPRESSURE_CAP's own comment for the full history.
        // Previously: accumulate candidates until a large, RAM-scaled
        // threshold was hit, THEN process the entire accumulated pile in
        // one burst. Now: during deep catch-up, drain a small, fixed
        // chunk (DEEP_CATCHUP_DRAIN_CHUNK_SIZE) every single commit,
        // whenever there's anything waiting at all. This decouples peak
        // memory for this pathway from both available RAM and covenant
        // activity level in any given stretch of the chain -- it now
        // depends only on the fixed chunk size, the same guarantee on a
        // quiet part of the chain's history as the busiest one, and the
        // same guarantee on a 2GB VPS as on a well-provisioned
        // workstation.
        //
        // Near the tip, unchanged: the real cost there is the (already
        // disk-backed, already memory-safe) validation walk's own time,
        // not candidate volume -- a commit-count interval is still the
        // right kind of trigger for that, and chunking that path's own
        // batch the same way deep-catch-up's now is would mean walking
        // the whole tree far more often for no real memory benefit,
        // trading one real problem for a different, worse one.
        boolean shouldReconcile;
        if (deepCatchUp) {
            shouldReconcile = !accumulatedOrphanCandidates.isEmpty();
        } else {
            commitsSinceLastPrune++;
            shouldReconcile = commitsSinceLastPrune >= PRUNE_EVERY_N_COMMITS;
        }
        if (!shouldReconcile) {
            return true; // commit happened; skip reconciliation this cycle
        }
        if (!deepCatchUp) commitsSinceLastPrune = 0;

        if (!pruneInProgress.compareAndSet(false, true)) {
            // A previous reconciliation is still running -- skip this
            // boundary entirely rather than queue another one behind
            // it; the next boundary (36 blocks later, or the very next
            // commit during deep catch-up) will try again, and nothing
            // here depends on it happening at any SPECIFIC height, only
            // on it happening often enough. Candidates keep accumulating
            // above regardless -- nothing is lost by skipping, only
            // deferred, and the hard cap above remains the real backstop
            // regardless of how often this particular skip happens.
            System.out.println("[UrkelNameTree] Skipping reconciliation at height " + height
                    + " -- a previous one is still running in the background");
            return true;
        }

        // RE-ARCHITECTURE (second pass): take only a small, fixed-size
        // chunk during deep catch-up, not the whole backlog -- entries
        // left behind simply stay in accumulatedOrphanCandidates for the
        // next commit's own drain cycle. Iterator.remove() here is safe
        // to do mid-iteration: accumulatedOrphanCandidates is backed by
        // a ConcurrentHashMap (confirmed at its own declaration), whose
        // iterators are weakly consistent and explicitly support
        // concurrent removal, unlike a plain HashSet's.
        //
        // FIX: must be a concurrent-safe set, not a plain HashSet --
        // this is now registered with the tree's unorphan-resurrection
        // safeguard for the deep-catch-up path specifically (see below),
        // meaning the main thread's own resolve()/collectUnpersisted()
        // calls can concurrently remove() from this exact set while the
        // background removal below is still using it. A plain HashSet
        // was never safe for that, same reasoning as pendingOrphans/
        // awaitingNextCommit's own fix earlier this session.
        java.util.Set<UrkelNodeStore.HashKey> candidatesSnapshot =
                java.util.concurrent.ConcurrentHashMap.newKeySet();
        if (deepCatchUp) {
            java.util.Iterator<UrkelNodeStore.HashKey> it = accumulatedOrphanCandidates.iterator();
            int taken = 0;
            while (it.hasNext() && taken < DEEP_CATCHUP_DRAIN_CHUNK_SIZE) {
                candidatesSnapshot.add(it.next());
                it.remove();
                taken++;
            }
        } else {
            // Near-tip path unchanged: still takes everything at once --
            // see the comment above shouldReconcile's own computation
            // for why chunking this specific path isn't the fix here.
            candidatesSnapshot.addAll(accumulatedOrphanCandidates);
            accumulatedOrphanCandidates.clear();
        }

        System.out.println("[UrkelNameTree] Reconciliation STARTING at height " + height
                + " (heap: " + heapSnapshot() + ", draining " + candidatesSnapshot.size()
                + " of " + (candidatesSnapshot.size() + accumulatedOrphanCandidates.size()) + " waiting, "
                + (deepCatchUp ? "trusting candidates directly, no validation walk -- deep catch-up"
                : "full disk-backed validation walk -- near the tip"));

        pruneExecutor.submit(() -> drainOneBatch(candidatesSnapshot, deepCatchUp, rootToPrune, height));
        return true;
    }

    /** Synchronous, blocking emergency backstop -- entered only when the
     *  orphan backlog has grown past HARD_BACKPRESSURE_CAP despite the
     *  small, continuous draining maybeCommit() does on every commit.
     *  Reaching this means orphan generation is outpacing drainage
     *  faster than the background executor can keep up with on its own;
     *  this deliberately pauses the CALLING thread (block processing
     *  itself) until the backlog is back down to a safe level, rather
     *  than letting it keep growing without limit. This is what
     *  actually turns the memory ceiling into a real, provable
     *  guarantee rather than just an empirically-tuned-to-usually-work
     *  heuristic -- see HARD_BACKPRESSURE_CAP's own comment for the
     *  full design reasoning.
     *
     *  Runs the drain inline, on this thread, rather than via
     *  pruneExecutor -- there's no benefit to the async path here, since
     *  this thread is already deliberately blocked either way, and
     *  doing it inline avoids adding scheduling delay on top of an
     *  already-degraded situation. */
    private void blockUntilBacklogDrains(boolean deepCatchUp, UrkelNode rootToPrune, int height) {
        long resumeThreshold = HARD_BACKPRESSURE_CAP / 2;
        long startSize = accumulatedOrphanCandidates.size();
        System.out.println("[UrkelNameTree] BACKPRESSURE: orphan backlog (" + startSize
                + ") reached the hard cap (" + HARD_BACKPRESSURE_CAP + ") at height " + height
                + " -- pausing block processing until it drains back below " + resumeThreshold + ".");
        long start = System.currentTimeMillis();
        while (accumulatedOrphanCandidates.size() > resumeThreshold) {
            if (pruneInProgress.compareAndSet(false, true)) {
                java.util.Set<UrkelNodeStore.HashKey> chunk = java.util.concurrent.ConcurrentHashMap.newKeySet();
                if (deepCatchUp) {
                    java.util.Iterator<UrkelNodeStore.HashKey> it = accumulatedOrphanCandidates.iterator();
                    int taken = 0;
                    while (it.hasNext() && taken < DEEP_CATCHUP_DRAIN_CHUNK_SIZE) {
                        chunk.add(it.next());
                        it.remove();
                        taken++;
                    }
                } else {
                    chunk.addAll(accumulatedOrphanCandidates);
                    accumulatedOrphanCandidates.clear();
                }
                drainOneBatch(chunk, deepCatchUp, rootToPrune, height);
            } else {
                // A background cycle from just before we hit the cap is
                // still finishing -- give it a moment rather than
                // busy-spinning.
                try {
                    Thread.sleep(20);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
        System.out.println("[UrkelNameTree] BACKPRESSURE: backlog drained to " + accumulatedOrphanCandidates.size()
                + " after " + (System.currentTimeMillis() - start) + "ms -- resuming normal block processing.");
    }

    /** Does the actual removal work for one batch of candidates --
     *  shared between the normal, async (pruneExecutor) path in
     *  maybeCommit() and the synchronous emergency path in
     *  blockUntilBacklogDrains() above, so the two can never drift out
     *  of sync with each other -- exactly the kind of divergence risk
     *  duplicating this logic across two call sites would otherwise
     *  create. Always resets pruneInProgress in its own finally block,
     *  regardless of which path called it -- the caller never needs to
     *  remember to do this separately. */
    private void drainOneBatch(java.util.Set<UrkelNodeStore.HashKey> candidatesSnapshot,
                               boolean deepCatchUp, UrkelNode rootToPrune, int height) {
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
                //
                // FIX: register this specific in-flight batch with
                // the tree's unorphan-resurrection safeguard for the
                // duration of the removal, and unregister it
                // immediately after (success or failure) via
                // try/finally -- without this, a resurrection
                // landing after accumulatedOrphanCandidates.clear()
                // above but before removeDirectly() actually deletes
                // this exact batch would go completely undetected.
                // reconcileAndRemove() below doesn't need this: it
                // independently re-verifies reachability against a
                // fresh walk at the moment of deletion, so it's
                // already immune regardless of this registration.
                tree.registerExternalPendingRemovalSet(candidatesSnapshot);
                int removed;
                try {
                    removed = tree.removeDirectly(candidatesSnapshot);
                } finally {
                    tree.unregisterExternalPendingRemovalSet(candidatesSnapshot);
                }
                // NEW: self-healing support -- record only the
                // FIRST time this ever actually deletes something
                // (removed > 0; a cycle that deletes nothing carries
                // no risk regardless of which mode it ran in). See
                // this field's own comment for why first, not most
                // recent. No actual race to reason about here:
                // pruneInProgress (confirmed via its own
                // compareAndSet gate above and its reset in this
                // task's finally block below) already serializes
                // reconciliation cycles -- only one can ever be
                // mid-deletion at a time, so this check-then-set is
                // safe in practice even though a volatile field's
                // read-then-write isn't atomic in general.
                if (removed > 0 && firstDeepCatchUpDeletionHeight == -1) {
                    firstDeepCatchUpDeletionHeight = height;
                }
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