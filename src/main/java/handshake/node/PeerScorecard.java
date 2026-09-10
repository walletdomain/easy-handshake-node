package handshake.node;


import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * PeerScorecard — tracks peer quality and manages connection backoffs.
 * <p>
 * Persists through ConfigDB's real "peerScores" map (recovered from an
 * earlier version of this project) instead of ChainDB. That real format
 * is comma-delimited:
 * <p>
 *   score,f1,failureCount,f3,successCount,backoffLevel,t1,t2,t3,height,agent
 * <p>
 * Field meanings below are a mix of confirmed and inferred -- see the
 * project notes for the methodology. CONFIRMED (clear, unambiguous
 * pattern across all 30 real entries): score (field 0, strictly 0/50/100),
 * backoffLevel (field 5, range 0-3 matching this class's own convention),
 * height (field 9, clustered around plausible real chain heights), agent
 * (field 10, "/hsd:x.y.z/.../" strings). INFERRED, moderate confidence:
 * failureCount (field 2, correlates inversely with score) and
 * successCount (field 4, correlates with known long-lived good peers).
 * The three timestamps (fields 6-8) are inferred to be lastAttempt,
 * lastSuccess, and lastFailure respectively based on relative recency,
 * but the exact assignment is a guess. Fields 1 and 3 have NO confirmed
 * or guessed meaning -- they're preserved verbatim on read-modify-write
 * (as extra1/extra3) rather than dropped, since discarding unknown data
 * on every save would silently destroy whatever they represent.
 * <p>
 * backoffUntil doesn't appear in the real 11-field format at all (it's
 * presumably computed live rather than persisted in whatever app wrote
 * this data). It's appended here as a 12th field on write; reading
 * tolerates both the original 11-field format and this extended one.
 * <p>
 * Design principles (unchanged from before):
 *   - Seeds are NEVER permanently blacklisted — max 30min backoff
 *   - Discovered peers can be blacklisted but reset on restart
 *   - All backoffs reset on startup (stale scores cause connectivity issues)
 *   - Score decay: peers slowly recover over time
 *   - Thread-safe: called from P2P threads concurrently
 */
public class PeerScorecard {

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static final PeerScorecard INSTANCE = new PeerScorecard();
    public static PeerScorecard get() { return INSTANCE; }

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final int   SCORE_INITIAL          = 50; // known, curated seeds
    private static final int   SCORE_INITIAL_DISCOVERED = 25; // unverified, gossiped peers -- must earn trust
    private static final int   SCORE_SUCCESS_BONUS    = 5;
    private static final int   SCORE_BRONTIDE_BONUS   = 3;  // extra, on top of SCORE_SUCCESS_BONUS
    private static final int   SCORE_VALID_DATA_BONUS = 2;
    private static final int   SCORE_INVALID_DATA_PENALTY = 30; // heavier than a plain connection failure
    private static final int   SCORE_FAILURE_PENALTY  = 15;
    private static final int   SCORE_STALE_TIP_PENALTY = 3;
    private static final int   SCORE_MAX              = 100;
    private static final int   SCORE_BACKOFF_THRESHOLD = 25;
    private static final int   SCORE_BLACKLIST        = 0;

    // Latency-based scoring: consistently fast peers get a small bonus,
    // consistently slow ones a small penalty. Bounded and modest on
    // purpose -- this should nudge peer selection toward faster nodes,
    // not override everything else (brontide, valid-data track record).
    private static final double LATENCY_EMA_ALPHA        = 0.3;  // weight given to each new sample
    private static final double SCORE_FAST_THRESHOLD_MS  = 800;  // faster than this: small bonus
    private static final double SCORE_SLOW_THRESHOLD_MS  = 5000; // slower than this: small penalty
    private static final int    SCORE_LATENCY_ADJUST     = 1;

    private static final long[] BACKOFF_MS = {
            5  * 60_000L,   // 0: 5 minutes
            30 * 60_000L,   // 1: 30 minutes  ← seed cap
            2  * 3600_000L, // 2: 2 hours
            24 * 3600_000L  // 3: 24 hours    ← non-seed max
    };

    private static final int SEED_MAX_BACKOFF_LEVEL = 1;

    // ── Peer record ───────────────────────────────────────────────────────────

    public static class PeerRecord {
        public final String ip;
        public int    score;
        public int    backoffLevel;
        public long   backoffUntil;      // epoch ms; local-only, see class javadoc
        public int    successCount;      // inferred field
        public int    failureCount;      // inferred field
        public long   lastSuccessTime;   // inferred field
        public long   lastFailureTime;   // inferred field
        public long   lastAttemptTime;   // inferred field
        public String lastAgent;
        public int    lastHeight;
        public String extra1 = "0";      // unknown real-format field, preserved verbatim
        public String extra3 = "0";      // unknown real-format field, preserved verbatim
        public boolean usesBrontide;     // in-memory only, not part of the persisted format
        public int    validDataCount;    // in-memory only
        public int    invalidDataCount;  // in-memory only
        public double avgLatencyMs = -1; // in-memory only, exponential moving average; -1 = no data yet
        public boolean banned;           // in-memory only; permanent until process restart
        public String  banReason;        // in-memory only
        public long    banTime;          // in-memory only; epoch ms

        PeerRecord(String ip) {
            this.ip    = ip;
            // Curated seeds (a known, hand-picked list) start trusted;
            // peers discovered via ADDR gossip from other nodes are
            // essentially unverified random internet hosts reported by
            // someone else, and start with a meaningfully lower score so
            // the weighted selection prefers trying known-good seeds
            // first by default, rather than treating a freshly-gossiped,
            // possibly-dead host as equally trustworthy on day one. A
            // discovered peer that actually connects successfully will
            // climb from here via the normal scoring bonuses.
            this.score = SeedDatabase.get().isSeed(ip) ? SCORE_INITIAL : SCORE_INITIAL_DISCOVERED;
        }

        public boolean isBackedOff() {
            return System.currentTimeMillis() < backoffUntil;
        }

        public boolean isBlacklisted() {
            return score <= SCORE_BLACKLIST
                    && backoffLevel >= BACKOFF_MS.length - 1
                    && isBackedOff();
        }

        public String status() {
            if (isBlacklisted()) return "BLACKLISTED";
            if (isBackedOff())   return "BACKOFF(" + formatDuration(backoffUntil - System.currentTimeMillis()) + ")";
            if (score >= 70)     return "HEALTHY";
            if (score >= 40)     return "DEGRADED";
            return "POOR";
        }

        /** Comma-delimited, matching the real format, with backoffUntil appended as field 12. */
        public String toStorage() {
            return score + "," + extra1 + "," + failureCount + "," + extra3 + ","
                    + successCount + "," + backoffLevel + ","
                    + lastAttemptTime + "," + lastSuccessTime + "," + lastFailureTime + ","
                    + lastHeight + "," + (lastAgent != null ? lastAgent : "") + ","
                    + backoffUntil;
        }

        public static PeerRecord fromStorage(String ip, String s) {
            PeerRecord r = new PeerRecord(ip);
            try {
                String[] p = s.split(",", -1);
                r.score           = parseIntSafe(p, 0, 0);
                r.extra1          = p.length > 1 ? p[1] : "0";
                r.failureCount    = parseIntSafe(p, 2, 0);
                r.extra3          = p.length > 3 ? p[3] : "0";
                r.successCount    = parseIntSafe(p, 4, 0);
                r.backoffLevel    = parseIntSafe(p, 5, 0);
                r.lastAttemptTime = parseLongSafe(p, 6, 0);
                r.lastSuccessTime = parseLongSafe(p, 7, 0);
                r.lastFailureTime = parseLongSafe(p, 8, 0);
                r.lastHeight      = parseIntSafe(p, 9, 0);
                r.lastAgent       = p.length > 10 ? p[10] : "";
                r.backoffUntil    = parseLongSafe(p, 11, 0); // absent in original 11-field format
            } catch (Exception ignored) {}
            return r;
        }

        private static int parseIntSafe(String[] p, int i, int def) {
            if (i >= p.length) return def;
            try { return Integer.parseInt(p[i].trim()); } catch (Exception e) { return def; }
        }

        private static long parseLongSafe(String[] p, int i, long def) {
            if (i >= p.length) return def;
            try { return Long.parseLong(p[i].trim()); } catch (Exception e) { return def; }
        }
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final ConcurrentHashMap<String, PeerRecord> cache = new ConcurrentHashMap<>();
    private KVMap<String, String> peerScoresMap;

    private PeerScorecard() {}

    /**
     * Wires scorecard to persistent storage (ConfigDB's peerScores map)
     * and resets all backoffs. Must be called after ConfigDB is opened
     * (i.e. after NodeConfig.load(dataDir)).
     */
    public void init(ConfigDB configDb) {
        this.peerScoresMap = configDb.peerScoresMap();
        int loaded = 0;
        for (var e : peerScoresMap.entrySet()) {
            cache.put(e.getKey(), PeerRecord.fromStorage(e.getKey(), e.getValue()));
            loaded++;
        }
        System.out.printf("[PeerScore] Loaded %d peer records from the config database.%n", loaded);
        resetAllBackoffs();
    }

    // ── Score updates ─────────────────────────────────────────────────────────

    public void recordAttempt(String ip) {
        PeerRecord r = getOrCreate(ip);
        r.lastAttemptTime = System.currentTimeMillis();
        persist(r);
    }

    /** Records a successful connection. Brontide connections get a small
     *  bonus over cleartext, since they're authenticated/encrypted and
     *  therefore more trustworthy as a data source. */
    public void recordSuccess(String ip, String agent, int height, boolean brontide) {
        PeerRecord r = getOrCreate(ip);
        int bonus = SCORE_SUCCESS_BONUS + (brontide ? SCORE_BRONTIDE_BONUS : 0);
        r.score         = Math.min(SCORE_MAX, r.score + bonus);
        r.successCount++;
        r.lastSuccessTime = System.currentTimeMillis();
        r.lastAgent     = agent;
        r.lastHeight    = height;
        r.usesBrontide  = brontide;
        r.backoffLevel  = Math.max(0, r.backoffLevel - 1);
        r.backoffUntil  = 0;
        persist(r);
    }

    /** Backward-compatible overload defaulting to non-brontide (cleartext). */
    public void recordSuccess(String ip, String agent, int height) {
        recordSuccess(ip, agent, height, false);
    }

    /**
     * Records how long a request/response round trip took (e.g. a
     * GETHEADERS -> HEADERS exchange), folding it into a small scoring
     * bonus for consistently fast peers. Uses an exponential moving
     * average rather than the raw latest sample, so one unusually slow
     * or fast round trip doesn't swing the score dramatically.
     */
    public void recordLatency(String ip, long millis) {
        PeerRecord r = getOrCreate(ip);
        r.avgLatencyMs = r.avgLatencyMs < 0
                ? millis
                : (LATENCY_EMA_ALPHA * millis + (1 - LATENCY_EMA_ALPHA) * r.avgLatencyMs);

        // Fold speed into the score as a small, bounded adjustment rather
        // than a separate always-applied bonus, so it nudges ranking
        // without dominating the other signals (brontide, valid data,
        // etc.). Faster than SCORE_FAST_THRESHOLD_MS: small bonus. Slower
        // than SCORE_SLOW_THRESHOLD_MS: small penalty. In between: no
        // change.
        if (r.avgLatencyMs < SCORE_FAST_THRESHOLD_MS) {
            r.score = Math.min(SCORE_MAX, r.score + SCORE_LATENCY_ADJUST);
        } else if (r.avgLatencyMs > SCORE_SLOW_THRESHOLD_MS) {
            r.score = Math.max(0, r.score - SCORE_LATENCY_ADJUST);
        }
        persist(r);
    }

    /** Records that a peer sent us a header or block that validated
     *  correctly (hash matched, chained properly, etc.). */
    public void recordValidData(String ip) {
        PeerRecord r = getOrCreate(ip);
        r.score = Math.min(SCORE_MAX, r.score + SCORE_VALID_DATA_BONUS);
        r.validDataCount++;
        persist(r);
    }

    /** Records that a peer sent us a header or block that FAILED
     *  validation (bad hash, doesn't chain, etc.) -- a much heavier
     *  penalty than a simple connection failure, since this indicates
     *  the peer is actively sending bad data rather than just being
     *  temporarily unreachable. */
    public void recordInvalidData(String ip, String reason) {
        PeerRecord r = getOrCreate(ip);
        r.score = Math.max(0, r.score - SCORE_INVALID_DATA_PENALTY);
        r.invalidDataCount++;
        persist(r);
        System.out.printf("[PeerScore] %s sent invalid data (score now %d): %s%n",
                ip, r.score, reason);
        if (r.score < SCORE_BACKOFF_THRESHOLD) {
            applyBackoff(ip, r);
            persist(r);
        }
    }

    /** Records a connection failure. Seeds are capped at 30min backoff. */
    public void recordFailure(String ip, String reason) {
        PeerRecord r = getOrCreate(ip);
        r.score         = Math.max(0, r.score - SCORE_FAILURE_PENALTY);
        r.failureCount++;
        r.lastFailureTime = System.currentTimeMillis();

        if (r.score < SCORE_BACKOFF_THRESHOLD) {
            applyBackoff(ip, r);
        }
        persist(r);

        if (r.isBlacklisted()) {
            System.out.printf("[PeerScore] %s blacklisted (score=%d, %s): %s%n",
                    ip, r.score, r.status(), reason);
        } else if (r.isBackedOff()) {
            System.out.printf("[PeerScore] %s backoff %s: %s%n",
                    ip, formatDuration(r.backoffUntil - System.currentTimeMillis()), reason);
        }
    }

    /** Records a stale tip (peer height below ours). Light penalty. */
    public void recordStaleTip(String ip, int peerHeight, int ourHeight) {
        PeerRecord r = getOrCreate(ip);
        r.score = Math.max(0, r.score - SCORE_STALE_TIP_PENALTY);
        r.lastHeight = peerHeight;
        persist(r);
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    public boolean shouldSkip(String ip) {
        PeerRecord r = cache.get(ip);
        return r != null && (r.banned || r.isBackedOff());
    }

    /**
     * Permanently bans a peer for the remainder of this process's
     * lifetime -- distinct from the existing temporary backoff, which is
     * meant for peers that are merely unreliable or currently
     * unreachable. A ban is reserved for signals strong enough that a
     * genuinely honest, correctly-functioning validator could not plausibly
     * have produced them -- invalid proof-of-work being the clearest
     * example, since any honest relay verifies PoW before ever
     * forwarding a header. A single chain-link mismatch, by contrast,
     * can happen for entirely benign reasons (a brief reorg, a stale
     * tip) and stays as a scored/backed-off signal rather than an
     * outright ban.
     */
    public void banPeer(String ip, String reason) {
        PeerRecord r = getOrCreate(ip);
        r.banned = true;
        r.banReason = reason;
        r.banTime = System.currentTimeMillis();
        r.score = 0;
        persist(r);
        System.out.printf("[PeerScore] BANNED %s: %s%n", ip, reason);
    }

    /** Matches real hsd's "setban ... remove" -- lifts a ban on one peer. */
    public void unbanPeer(String ip) {
        PeerRecord r = cache.get(ip);
        if (r != null) {
            r.banned = false;
            r.banReason = null;
            persist(r);
        }
    }

    /** Matches real hsd's "listbanned". */
    public List<PeerRecord> listBannedPeers() {
        return cache.values().stream().filter(r -> r.banned).toList();
    }

    /** Matches real hsd's "clearbanned" -- lifts every ban at once. */
    public void clearAllBans() {
        for (PeerRecord r : cache.values()) {
            if (r.banned) {
                r.banned = false;
                r.banReason = null;
                persist(r);
            }
        }
    }

    public boolean isBanned(String ip) {
        PeerRecord r = cache.get(ip);
        return r != null && r.banned;
    }

    public boolean isGood(String ip) {
        PeerRecord r = cache.get(ip);
        return r == null || (!r.isBackedOff() && r.score >= SCORE_BACKOFF_THRESHOLD);
    }

    public PeerRecord getRecord(String ip) {
        return cache.get(ip);
    }

    public List<PeerRecord> getAllRecords() {
        return new ArrayList<>(cache.values());
    }

    public List<PeerRecord> getRankedPeers() {
        return cache.values().stream()
                .filter(r -> !r.isBackedOff())
                .sorted((a, b) -> Integer.compare(b.score, a.score))
                .toList();
    }

    /**
     * Given a list of IPs, returns them reordered to favor higher scores
     * while still varying run to run -- true weighted random sampling
     * without replacement (probability of being picked next is
     * proportional to score), NOT a strict score-descending sort (always
     * hammering the same top peer) and NOT a pure shuffle (ignoring
     * score entirely). A peer with 90 will usually rank ahead of one
     * with 20, but not always -- and this holds regardless of how large
     * or small the score gap is, unlike a fixed additive jitter range.
     */
    public List<String> weightedOrder(List<String> ips) {
        List<String> pool = new ArrayList<>(ips);
        List<Integer> weights = new ArrayList<>();
        for (String ip : pool) weights.add(Math.max(1, scoreOf(ip))); // never zero weight

        java.util.Random rnd = new java.util.Random();
        List<String> result = new ArrayList<>(pool.size());
        while (!pool.isEmpty()) {
            int total = weights.stream().mapToInt(Integer::intValue).sum();
            int r = rnd.nextInt(total);
            int cumulative = 0;
            int chosen = 0;
            for (int i = 0; i < weights.size(); i++) {
                cumulative += weights.get(i);
                if (r < cumulative) { chosen = i; break; }
            }
            result.add(pool.remove(chosen));
            weights.remove(chosen);
        }
        return result;
    }

    private int scoreOf(String ip) {
        PeerRecord r = cache.get(ip);
        return r != null ? r.score : SCORE_INITIAL;
    }

    // ── Backoff ───────────────────────────────────────────────────────────────

    private void applyBackoff(String ip, PeerRecord r) {
        boolean isSeed = SeedDatabase.get().isSeed(ip);
        int maxLevel = isSeed ? SEED_MAX_BACKOFF_LEVEL : BACKOFF_MS.length - 1;
        r.backoffLevel = Math.min(r.backoffLevel + 1, maxLevel);
        r.backoffUntil = System.currentTimeMillis() + BACKOFF_MS[r.backoffLevel];
        if (isSeed) {
            r.score = Math.max(r.score, SCORE_BACKOFF_THRESHOLD);
        }
    }

    public void resetAllBackoffs() {
        int reset = 0;
        for (PeerRecord r : cache.values()) {
            if (r.isBackedOff() || r.isBlacklisted()) {
                r.backoffUntil = 0;
                r.backoffLevel = 0;
                r.score = Math.max(r.score, SCORE_BACKOFF_THRESHOLD);
                persist(r);
                reset++;
            }
        }
        if (reset > 0)
            System.out.printf("[PeerScore] Reset %d peer backoff(s).%n", reset);
    }

    public void applyDecay() {
        long now = System.currentTimeMillis();
        for (PeerRecord r : cache.values()) {
            if (r.score < SCORE_MAX && r.lastSuccessTime > 0) {
                long minutesSinceSuccess = (now - r.lastSuccessTime) / 60_000;
                if (minutesSinceSuccess < 60) {
                    r.score = Math.min(SCORE_MAX, r.score + 1);
                    persist(r);
                }
            }
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    private PeerRecord getOrCreate(String ip) {
        return cache.computeIfAbsent(ip, PeerRecord::new);
    }

    private void persist(PeerRecord r) {
        if (peerScoresMap != null) {
            peerScoresMap.put(r.ip, r.toStorage());
            ConfigDB.get().commit();
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static String formatDuration(long ms) {
        if (ms <= 0) return "0s";
        long s = ms / 1000;
        if (s < 60)   return s + "s";
        if (s < 3600) return (s / 60) + "m";
        return (s / 3600) + "h " + ((s % 3600) / 60) + "m";
    }
}