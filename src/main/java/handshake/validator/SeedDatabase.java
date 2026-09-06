package handshake.validator;

import org.h2.mvstore.MVMap;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * SeedDatabase — loads known Handshake seed nodes from ConfigDB's real
 * "seeds" map (recovered from an earlier version of this project),
 * replacing the previous hardcoded-in-Java list.
    * <p>
 * Real format found in the recovered data: for a key = ip, the value is
 *   brontideKey|port|source|<blank 4th field, meaning unconfirmed>|isBuiltin
 * A separate tombstone convention also exists: a key "deleted:<ip>" with
 * value "true" marks a seed as permanently removed (distinct from
 * PeerScorecard's temporary backoff) -- entries with such a tombstone
 * are skipped on load.
    * <p>
 * Design principles (unchanged from before):
 *   - Seeds are NEVER permanently blacklisted by THIS class — only
 *     temporarily backed off, and that's PeerScorecard's job, not this
 *     class's. The "deleted:" tombstone is a different, harder removal
 *     that was apparently made deliberately in the recovered data (e.g.
 *     to drop a seed that turned out to be unreliable) -- it isn't
 *     re-added here even though seeds are otherwise never blacklisted,
 *     since honoring an explicit prior removal is different from this
 *     class deciding to blacklist something itself.
 *   - New seeds discovered at runtime are persisted back into the same
 *     "seeds" map (isBuiltin=false) so they survive restarts.
 */
public class SeedDatabase {

    // ── Seed record ───────────────────────────────────────────────────────────

    /**
     * A known seed validator.
        * <p>
     * @param brontideKey  Base32-encoded compressed secp256k1 public key (33 bytes)
     *                     Empty string for cleartext-only peers (port 12038)
     * @param ip           IPv4 or IPv6 address
     * @param port         P2P port (44806 for Brontide, 12038 for cleartext)
     * @param label        Human-readable label for logging
     * @param builtin      Whether this came from the curated seed set vs. runtime discovery
     */
    public record Seed(
            String brontideKey,
            String ip,
            int    port,
            String label,
            boolean builtin
    ) {
        public boolean hasBrontideKey() {
            return brontideKey != null && !brontideKey.isBlank();
        }

        public boolean isCleartext() {
            return port == 12038 || !hasBrontideKey();
        }

        String toStorage() {
            return brontideKey + "|" + port + "|" + label + "||" + builtin;
        }

        static Seed fromStorage(String ip, String s) {
            String[] p = s.split("\\|", -1);
            String key = p.length > 0 ? p[0] : "";
            int port = p.length > 1 ? parseIntSafe(p[1], 44806) : 44806;
            String label = p.length > 2 ? p[2] : "seed";
            boolean builtin = p.length > 4 && "true".equalsIgnoreCase(p[4]);
            return new Seed(key, ip, port, label, builtin);
        }

        private static int parseIntSafe(String s, int def) {
            try { return Integer.parseInt(s.trim()); } catch (Exception e) { return def; }
        }

        @Override
        public String toString() {
            return label + " (" + ip + ":" + port + ")";
        }
    }

    // ── Singleton ─────────────────────────────────────────────────────────────
    //
    // Lazily initialized on first get() rather than eagerly at class-load
    // time, since it depends on ConfigDB already being open (NodeConfig.load()
    // opens it during normal startup, which happens before anything calls
    // SeedDatabase.get() in Main.java's sequence -- but unlike the previous
    // version's static-init bug, this fails loudly if that ordering is ever
    // violated instead of silently crashing or reading empty data.

    private static volatile SeedDatabase instance;

    public static SeedDatabase get() {
        if (instance == null) {
            synchronized (SeedDatabase.class) {
                if (instance == null) instance = new SeedDatabase();
            }
        }
        return instance;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final MVMap<String, String> seedsMap;
    private final List<Seed> seeds = new CopyOnWriteArrayList<>();

    private SeedDatabase() {
        ConfigDB db;
        try {
            db = ConfigDB.get();
        } catch (IllegalStateException e) {
            throw new IllegalStateException(
                    "SeedDatabase.get() was called before ConfigDB was opened "
                            + "(NodeConfig.load(dataDir) must run first)", e);
        }
        this.seedsMap = db.seedsMap();
        loadFromDb();
        bootstrapIfEmpty();
    }

    private void loadFromDb() {
        int loaded = 0, skippedDeleted = 0;
        for (var entry : seedsMap.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith("deleted:")) continue; // tombstones handled below
            String ip = key;
            if (isDeleted(ip)) {
                skippedDeleted++;
                continue;
            }
            seeds.add(Seed.fromStorage(ip, entry.getValue()));
            loaded++;
        }
        System.out.printf("[SeedDB] Loaded %d seeds from config_mv.db (%d tombstoned/skipped).%n",
                loaded, skippedDeleted);
    }

    private boolean isDeleted(String ip) {
        return "true".equalsIgnoreCase(seedsMap.get("deleted:" + ip));
    }

    // ── Bootstrap seeds ───────────────────────────────────────────────────────
    //
    // Used ONLY to populate the "seeds" map on a genuinely fresh install
    // (empty map, no config_mv.db carried over). Without this, a first-run
    // validator would load zero seeds from an empty DB and have no way to ever
    // discover its first peer -- ChainSync only dials from
    // getBrontideSeeds(), and PeerDiscovery starts empty too. These are the
    // same 10 real, verified entries recovered from a working config_mv.db
    // (the 3 that database had explicitly marked "deleted:<ip>" -- found
    // to be bad in production -- are deliberately excluded here too).
    private static final List<Seed> BOOTSTRAP_SEEDS = List.of(
            new Seed("ai7dgiwueiiwber6uhoeqfjdujxph6ueqpnaml36sicakngmnm3am", "103.152.197.114", 44806, "Nathan.Woodburn/3", true),
            new Seed("aokj73pefmtrc7ikoxqiz4nrhgrxeqnnjpv4wxekteup33duneih2", "103.152.197.115", 44806, "Nathan.Woodburn/2", true),
            new Seed("ajd6wzdp34c32rymlljybvbosnx75aty4rwmtpkxshvfrqufq6vuk", "103.152.197.116", 44806, "Nathan.Woodburn/1", true),
            new Seed("aksygghkgmciomeldjf5sc6rs2sgn2m34zfdz4xr7z5vguqvjis4e", "129.153.177.220", 44806, "seed-4", true),
            new Seed("am2lsmbzzxncaptqjo22jay3mztfwl33bxhkp7icfx7kmi5rvjaic", "139.162.183.168", 44806, "seed-5", true),
            new Seed("apt4rf2dfyelbivg63u47wykvdjtsl4kxzfdylkaae5s5ydldlnwu", "159.69.46.23", 44806, "seed-3", true),
            new Seed("aoihqqagbhzz6wxg43itefqvmgda4uwtky362p22kbimcyg5fdp54", "172.104.214.189", 44806, "seed-2", true),
            new Seed("aiwykdz37okry3pb2lzdsgbxeg72uky2zckxmiapzstpqqmb2hnge", "35.154.209.88", 44806, "handshake-micro-grants", true),
            new Seed("ap5vuwabzwyz6akhesanada4skhetd2jsvpkwuqxzuaoovn5ez4xg", "45.79.134.225", 44806, "seed-1", true),
            new Seed("anbwqus4a45bwiztei62lf2jiurzbsakzm7z2oz4oqug3ea5i3sac", "74.208.31.75", 44806, "relay-validator", true)
    );

    private void bootstrapIfEmpty() {
        if (!seeds.isEmpty()) return;
        System.out.println("[SeedDB] seeds map is empty (fresh install) -- populating "
                + BOOTSTRAP_SEEDS.size() + " built-in bootstrap seeds.");
        for (Seed seed : BOOTSTRAP_SEEDS) {
            seeds.add(seed);
            seedsMap.put(seed.ip(), seed.toStorage());
        }
        ConfigDB.get().commit();
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /** Returns all seeds (loaded + any added at runtime). */
    public List<Seed> getSeeds() {
        return Collections.unmodifiableList(seeds);
    }

    /** Returns only Brontide-capable seeds. */
    public List<Seed> getBrontideSeeds() {
        return seeds.stream()
                .filter(Seed::hasBrontideKey)
                .toList();
    }

    /** Returns only cleartext seeds. */
    public List<Seed> getCleartextSeeds() {
        return seeds.stream()
                .filter(Seed::isCleartext)
                .toList();
    }

    /** Returns the seed for a given IP, or null. */
    public Seed getSeedByIp(String ip) {
        return seeds.stream()
                .filter(s -> s.ip().equals(ip))
                .findFirst()
                .orElse(null);
    }

    /** Returns true if the IP is a known (non-deleted) seed. */
    public boolean isSeed(String ip) {
        return seeds.stream().anyMatch(s -> s.ip().equals(ip));
    }

    /**
     * Adds a dynamically discovered seed (e.g. from ADDR messages) and
     * persists it into config_mv.db's "seeds" map (isBuiltin=false) so it
     * survives restarts. Only added if not already known or previously
     * deleted.
     */
    public void addDiscovered(String brontideKey, String ip, int port, String label) {
        if (isSeed(ip) || isDeleted(ip)) return;
        Seed seed = new Seed(brontideKey, ip, port, label, false);
        seeds.add(seed);
        seedsMap.put(ip, seed.toStorage());
        ConfigDB.get().commit();
    }

    public int size() { return seeds.size(); }
}