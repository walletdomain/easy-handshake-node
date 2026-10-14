package handshake.node.chain;

/**
 * Network consensus parameters used by the block/transaction validators.
 * Values are copied from hsd lib/protocol/networks.js. MAINNET is what the
 * node runs; REGTEST exists so the validators can be differential-tested
 * against a short hsd regtest chain (same code, small timing constants).
 */
public final class ConsensusParams {
    public final String type;
    public final int coinbaseMaturity;
    public final int halvingInterval;
    public final int deflationHeight;
    // names
    public final int auctionStart, rolloutInterval, lockupPeriod, renewalWindow, renewalPeriod,
            renewalMaturity, claimPeriod, alexaLockupPeriod, claimFrequency, biddingPeriod,
            revealPeriod, treeInterval, transferLockup, auctionMaturity;
    public final boolean noRollout, noReserved;

    private ConsensusParams(String type, int coinbaseMaturity, int halvingInterval, int deflationHeight,
                            int auctionStart, int rolloutInterval, int lockupPeriod, int renewalWindow,
                            int renewalPeriod, int renewalMaturity, int claimPeriod, int alexaLockupPeriod,
                            int claimFrequency, int biddingPeriod, int revealPeriod, int treeInterval,
                            int transferLockup, int auctionMaturity, boolean noRollout, boolean noReserved) {
        this.type = type;
        this.coinbaseMaturity = coinbaseMaturity;
        this.halvingInterval = halvingInterval;
        this.deflationHeight = deflationHeight;
        this.auctionStart = auctionStart;
        this.rolloutInterval = rolloutInterval;
        this.lockupPeriod = lockupPeriod;
        this.renewalWindow = renewalWindow;
        this.renewalPeriod = renewalPeriod;
        this.renewalMaturity = renewalMaturity;
        this.claimPeriod = claimPeriod;
        this.alexaLockupPeriod = alexaLockupPeriod;
        this.claimFrequency = claimFrequency;
        this.biddingPeriod = biddingPeriod;
        this.revealPeriod = revealPeriod;
        this.treeInterval = treeInterval;
        this.transferLockup = transferLockup;
        this.auctionMaturity = auctionMaturity;
        this.noRollout = noRollout;
        this.noReserved = noReserved;
    }

    private static final int DAY = 144;

    public static final ConsensusParams MAINNET = new ConsensusParams("main", 100, 170000, 61043,
            14 * DAY, 7 * DAY, 30 * DAY, 2 * 365 * DAY, 182 * DAY, 30 * DAY, 4 * 365 * DAY, 8 * 365 * DAY,
            2 * DAY, 5 * DAY, 10 * DAY, DAY >>> 2, 2 * DAY, (5 + 10 + 14) * DAY, false, false);

    public static final ConsensusParams REGTEST = new ConsensusParams("regtest", 2, 2500, 200,
            0, 2, 2, 5000, 2500, 50, 250000, 500000,
            0, 5, 10, 5, 10, 5 + 10 + 50, false, false);

    /** Consensus-critical money constants (consensus.js). */
    public static final long COIN = 1_000_000L;
    public static final long MAX_MONEY = 2_040_000_000L * COIN;
    public static final long BASE_REWARD = 2000L * COIN;
    public static final int MAX_BLOCK_SIZE = 1_000_000;
    public static final int MAX_BLOCK_WEIGHT = 4_000_000;
    public static final int MAX_BLOCK_SIGOPS = 80_000;
    public static final int MAX_BLOCK_OPENS = 300;
    public static final int MAX_BLOCK_UPDATES = 600;
    public static final int MAX_BLOCK_RENEWALS = 600;
    public static final int MAX_TX_SIZE = 1_000_000;
    public static final int MAX_TX_WEIGHT = 4_000_000;
    public static final int MAX_RESOURCE_SIZE = 512;
    public static final int MAX_COVENANT_SIZE = (1 + 32) + (1 + 4) + (2 + MAX_RESOURCE_SIZE) + (1 + 32);

    public long subsidy(int height) {
        int halvings = height / halvingInterval;
        if (halvings >= 52) return 0;
        return BASE_REWARD >> halvings;
    }
}