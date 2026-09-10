package handshake.node;

import java.io.File;
import java.util.Map;

/**
 * ConfigDB — owns the shared storage engine handle that holds validator
 * configuration, seed addresses, peer scores, and discovered peers
 * (settings / seeds / peerScores / discoveredPeers maps).
 * <p>
 * This exists because all four of those maps live in ONE physical
 * database, and a single storage engine handle only allows one open
 * instance at a time -- NodeConfig, SeedDatabase, and PeerScorecard
 * can't each open their own handle on the same underlying data
 * independently. This class is the single owner; the other three
 * classes go through it, entirely via the KVStore/KVMap abstraction --
 * none of them know or care which concrete engine is actually
 * underneath.
 * <p>
 * Directory name: kept as "config" for continuity with the file this
 * used to be (the recovered database was literally named
 * "config_mv.db") -- now a RocksDB directory rather than a single H2
 * file, matching ChainDB's own migration for the same reasons (see
 * RocksDBKVStore's own class comment).
 */
public final class ConfigDB {

    private static volatile ConfigDB instance;

    public static synchronized ConfigDB open(String dataDir) {
        if (instance == null) {
            instance = new ConfigDB(dataDir);
        }
        return instance;
    }

    public static ConfigDB get() {
        if (instance == null) throw new IllegalStateException("ConfigDB not opened");
        return instance;
    }

    private final KVStore store;
    private final KVMap<String, String> settings;
    private final KVMap<String, String> seeds;
    private final KVMap<String, String> peerScores;
    private final KVMap<String, String> discoveredPeers;

    private ConfigDB(String dataDir) {
        String path = dataDir + "/config";
        File parent = new File(path).getParentFile();
        if (parent != null) parent.mkdirs();

        this.store = new RocksDBKVStore(path);
        this.settings = store.openStringStringMap("settings");
        this.seeds = store.openStringStringMap("seeds");
        this.peerScores = store.openStringStringMap("peerScores");
        this.discoveredPeers = store.openStringStringMap("discoveredPeers");
    }

    public KVMap<String, String> settingsMap() { return settings; }
    public KVMap<String, String> seedsMap() { return seeds; }
    public KVMap<String, String> peerScoresMap() { return peerScores; }
    public KVMap<String, String> discoveredPeersMap() { return discoveredPeers; }

    public Map<String, String> settingsSnapshot() { return settings.asUnmodifiableMap(); }

    public void commit() {
        store.commit();
    }

    public void close() {
        store.close();
    }
}