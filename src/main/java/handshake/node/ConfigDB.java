package handshake.node;

import org.h2.mvstore.MVMap;
import org.h2.mvstore.MVStore;

import java.io.File;
import java.util.Map;

/**
 * ConfigDB — owns the shared H2 MVStore file that holds node configuration,
 * seed addresses, peer scores, and discovered peers (settings / seeds /
 * peerScores / discoveredPeers maps).
    * <p>
 * This exists because all four of those maps live in ONE physical file
 * (the "config_mv.db" recovered from the earlier project), and H2's
 * MVStore only allows one open handle per file at a time -- NodeConfig,
 * SeedDatabase, and PeerScorecard can't each open their own MVStore on
 * the same file independently. This class is the single owner; the other
 * three classes go through it.
    * <p>
 * File name: the recovered database was literally named "config_mv.db"
 * (not the more typical "config.mv.db"), so that's what's used here to
 * match the real file rather than assume a renamed convention.
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

    private final MVStore store;
    private final MVMap<String, String> settings;
    private final MVMap<String, String> seeds;
    private final MVMap<String, String> peerScores;
    private final MVMap<String, String> discoveredPeers;

    private ConfigDB(String dataDir) {
        String path = dataDir + "/config_mv.db";
        File parent = new File(path).getParentFile();
        if (parent != null) parent.mkdirs();

        this.store = new MVStore.Builder()
                .fileName(path)
                .compress()
                .open();
        this.settings = store.openMap("settings");
        this.seeds = store.openMap("seeds");
        this.peerScores = store.openMap("peerScores");
        this.discoveredPeers = store.openMap("discoveredPeers");
    }

    public MVMap<String, String> settingsMap() { return settings; }
    public MVMap<String, String> seedsMap() { return seeds; }
    public MVMap<String, String> peerScoresMap() { return peerScores; }
    public MVMap<String, String> discoveredPeersMap() { return discoveredPeers; }

    public Map<String, String> settingsSnapshot() { return Map.copyOf(settings); }

    public void commit() {
        store.commit();
    }

    public void close() {
        store.close();
    }
}
