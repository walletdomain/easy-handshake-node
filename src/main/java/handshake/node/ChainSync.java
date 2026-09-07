package handshake.node;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/**
 * ChainSync — synchronizes the node with the Handshake network.
 * <p>
 * Responsibilities:
 *   1. Header sync: download all block headers from peers
 *   2. Block download: fetch full blocks for the header chain
 *   3. Block validation: verify proof-of-work and structure
 *   4. UTXO/name state updates: process covenants in confirmed blocks
 *   5. Peer management: connect to peers, detect stale tips
 * <p>
 * Design principles (learned from easy-handshake debugging):
 *   - Header tip is capped at peer tip + 2016 to prevent fake inflation
 *   - Auto-rollback when all peers report lower height than our tip
 *   - Block downloads use separate threads from header sync
 *   - Wallet/DNS notification via RpcServer.BlockListener
 * <p>
 * Sync lifecycle:
 *   HEADERS:  Connect to peer → send GETHEADERS → receive HEADERS
 *   BLOCKS:   Send GETBLOCKS → receive INV → send GETDATA → receive BLOCK
 *   STEADY:   Poll for new blocks every 60 seconds
 */
public class ChainSync {

    // ── Constants ─────────────────────────────────────────────────────────────

    private static final int POLL_INTERVAL_SEC  = 60;
    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS    = 30_000;
    private static final int MAX_HEADERS_BATCH  = 2000;
    private static final int MAX_BLOCK_BATCH    = 16;


    /** How many blocks to accumulate before committing to disk, rather
     *  than committing after every single block (see downloadBlocks()
     *  for why the previous unbatched behavior caused a real, worsening
     *  slowdown as the database grew). */
    private static final int BLOCK_COMMIT_INTERVAL = 100;
    private static final int HANDSHAKE_TIMEOUT  = 10_000;

    // P2P message types -- real values from hsd's lib/net/packets.js exports.types,
    // confirmed via probe script against a real hsd installation. Previous values
    // here were guessed and several were wrong: TX/BLOCK were swapped, and
    // HEADERS/SENDHEADERS collided with totally different real types
    // (MEMPOOL=16, PROOF=27).
    private static final int MSG_VERSION     = 0;
    private static final int MSG_VERACK      = 1;
    private static final int MSG_PING        = 2;
    private static final int MSG_PONG        = 3;
    private static final int MSG_GETADDR     = 4;
    private static final int MSG_ADDR        = 5;
    private static final int MSG_INV         = 6;
    private static final int MSG_GETDATA     = 7;
    private static final int MSG_NOTFOUND    = 8;
    private static final int MSG_GETBLOCKS   = 9;
    private static final int MSG_GETHEADERS  = 10;
    private static final int MSG_HEADERS     = 11;
    private static final int MSG_SENDHEADERS = 12;
    private static final int MSG_BLOCK       = 13;
    private static final int MSG_TX          = 14;
    private static final int MSG_REJECT      = 15;
    private static final int MSG_MEMPOOL     = 16;

    // Real hsd frame wrapper (goes INSIDE the Brontide-encrypted payload):
    // magic(4 LE) + cmd(1) + length(4 LE) + payload(N). No checksum, 9-byte
    // header. Previously entirely missing -- messages were sent as raw
    // payload with no magic/length wrapper at all, which is why peers
    // accepted our Act1/2/3 (crypto layer, now correct) but never responded
    // to our VERSION message (application layer, was malformed).
    private static final int MAGIC_MAINNET = 0x5B6EF2D3;

    /**
     * Gates the noisy per-message hex dumps (full frame + encrypted wire
     * bytes on every single SEND/receive) added while debugging the
     * handshake layer earlier. That layer is now solved and verified --
     * these dumps fire on every message during header sync and block
     * download, which floods the console with output that's no longer
     * needed for normal operation. Error-path logging (decrypt failures,
     * bad magic, partial reads) stays on regardless, since those are rare
     * and genuinely useful when they do happen.
     */
    private static final boolean VERBOSE_WIRE_LOGGING = false;

    /**
     * Minimum score gap (current peer vs. the top-ranked candidate)
     * needed to justify disconnecting and reconnecting mid-sync. Real,
     * but not so small that ordinary scoring noise triggers constant
     * reconnects between every single header batch.
     */
    private static final int PEER_SWITCH_SCORE_MARGIN = 15;

    /**
     * After this many header batches on the same connection, rotate to a
     * different peer regardless of how well it's performing -- addresses
     * a real gap where score-based switching alone tends to keep using
     * the same peer indefinitely, since it's the only one actively
     * earning fresh score points while every other candidate sits
     * static. At 2000 headers/batch this is roughly 20,000 headers per
     * peer before a mandatory rotation.
     */
    private static final int MAX_BATCHES_PER_PEER = 10;

    // NetAddress wire format (88 bytes exactly), used inside the VERSION payload.
    private static final int NET_ADDRESS_SIZE = 88;

    private static final int PROTOCOL_VERSION = 3;

    /** Built dynamically, not a fixed constant -- incorporates
     *  NodeConfig.VERSION (the single, authoritative version string also
     *  used by the console banner and RPC's subversion field) plus an
     *  optional operator-set comment, matching real hsd's own
     *  "/name:version/comment/" convention (comment omitted entirely
     *  when empty, same as hsd's own default behavior).
     *
     *  The P2P wire format's agent-length field is a single byte (max
     *  255, confirmed against this same class's own VERSION-message
     *  parsing code) -- a long or emoji-heavy comment could push the
     *  UTF-8-encoded string past that and silently corrupt the
     *  handshake, so the comment is truncated to fit if needed, safely
     *  at a whole-code-point boundary (never splitting a multi-byte
     *  UTF-8 sequence, which would produce invalid, corrupted bytes
     *  instead of just a shorter string). */
    private String userAgent() {
        String prefix = "/easy-handshake-node:" + NodeConfig.VERSION + "/";
        String comment = config.getUserAgentComment();
        if (comment == null || comment.isBlank()) return prefix;

        int maxCommentBytes = 255 - prefix.getBytes(java.nio.charset.StandardCharsets.UTF_8).length - 1; // trailing "/"
        String truncated = truncateToUtf8ByteLimit(comment, maxCommentBytes);
        return prefix + truncated + "/";
    }

    private static String truncateToUtf8ByteLimit(String s, int maxBytes) {
        if (maxBytes <= 0) return "";
        StringBuilder sb = new StringBuilder();
        int byteLen = 0;
        int i = 0;
        while (i < s.length()) {
            int cp = s.codePointAt(i);
            int cpCharCount = Character.charCount(cp);
            int cpByteLen = new String(Character.toChars(cp)).getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
            if (byteLen + cpByteLen > maxBytes) break;
            sb.appendCodePoint(cp);
            byteLen += cpByteLen;
            i += cpCharCount;
        }
        return sb.toString();
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private final NodeConfig   config;
    private final ChainDB      db;
    private final NodeIdentity identity;
    private final RpcServer    rpc;

    private volatile Mempool   mempool;
    private volatile boolean   running;
    /**
     * Set when syncHeaders() deliberately rotates away from a peer
     * (either a clear score-based switch or periodic forced
     * diversification), so the very next connectToBestPeer() call
     * actually tries someone different instead of weighted selection
     * just reconnecting to the same peer it was told to leave. Cleared
     * after that one use -- this is a one-shot nudge, not a lasting
     * exclusion.
     */
    private volatile String avoidPeerIp;

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "chain-sync");
                t.setDaemon(true);
                return t;
            });

    // Connected peer info for RPC
    private final List<PeerInfo> connectedPeers = new CopyOnWriteArrayList<>();

    // Sync statistics
    private final AtomicInteger blocksDownloaded = new AtomicInteger();
    private final AtomicLong    lastBlockTime    = new AtomicLong();

    public record PeerInfo(PeerConnection conn, long connTime, boolean inbound) {
        public String ip() { return conn.ip; }
    }

    /** Highest height any peer has ever reported, across all connections
     *  this session -- used by getblockchaininfo's verificationprogress
     *  as an honest "how far along are we" estimate, since this project
     *  has no other persistent notion of "the network's real height". */
    private volatile int bestKnownPeerHeight = 0;
    public int getBestKnownPeerHeight() { return bestKnownPeerHeight; }

    /** Cumulative wire bytes sent/received across all connections this
     *  session, for getnettotals. */
    private static final java.util.concurrent.atomic.AtomicLong totalBytesSent = new java.util.concurrent.atomic.AtomicLong();
    private static final java.util.concurrent.atomic.AtomicLong totalBytesRecv = new java.util.concurrent.atomic.AtomicLong();
    public static long getTotalBytesSent() { return totalBytesSent.get(); }
    public static long getTotalBytesRecv() { return totalBytesRecv.get(); }

    // ── Constructor ───────────────────────────────────────────────────────────

    public ChainSync(NodeConfig config, ChainDB db,
                     NodeIdentity identity, RpcServer rpc) {
        this.config   = config;
        this.db       = db;
        this.identity = identity;
        this.rpc      = rpc;
    }

    public void setMempool(Mempool mempool) {
        this.mempool = mempool;
        mempool.setRelayCallback(this::relayTxToPeers);
    }

    /**
     * Announces a newly-accepted mempool transaction to our currently
     * connected peers via INV (just the txid -- peers that want the
     * full data request it back via GETDATA, which serveGetData()
     * already handles). excludeIp is skipped so a transaction we just
     * received from a peer isn't immediately bounced right back to them.
     * <p>
     * Given outbound connections are transient (connect, sync a batch,
     * disconnect) rather than held open, this mostly reaches whichever
     * peers are currently connected to US (inbound) -- there's often no
     * active outbound connection at the moment a transaction is
     * accepted. Still a real, meaningful improvement over the previous
     * complete absence of relay: without this, any transaction reaching
     * this node (including via its own sendrawtransaction RPC) was a
     * dead end that would never propagate further.
     */
    private void relayTxToPeers(String txid, byte[] raw, String excludeIp) {
        byte[] txidBytes = fromHexStatic(txid);
        if (txidBytes == null || txidBytes.length != 32) return;

        byte[] invPayload = new byte[1 + 36];
        invPayload[0] = 1; // count = 1
        writeLE32(invPayload, 1, 1); // item type = 1 = TX
        System.arraycopy(txidBytes, 0, invPayload, 5, 32);

        for (PeerInfo p : connectedPeers) {
            if (p.ip().equals(excludeIp)) continue;
            try {
                p.conn().sendMessage(MSG_INV, invPayload);
            } catch (Exception e) {
                // best-effort -- a relay failure to one peer shouldn't
                // affect any other peer or the mempool acceptance itself
            }
        }
    }

    private static byte[] fromHexStatic(String s) {
        try {
            byte[] b = new byte[s.length() / 2];
            for (int i = 0; i < b.length; i++)
                b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
            return b;
        } catch (Exception e) {
            return null;
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() {
        verifyGenesisOrReset();
        verifyTipConsistencyOrTrim();
        running = true;
        scheduler.scheduleWithFixedDelay(
                this::syncCycle, 0, POLL_INTERVAL_SEC, TimeUnit.SECONDS);
    }

    /**
     * Self-healing check for exactly the scenario that caused a lot of
     * confusion during development: a chain database whose stored genesis
     * header (height 0) predates some fix and no longer matches the real
     * network's genesis hash. Previously this required manually deleting
     * the whole data directory to recover -- if it's ever wrong again for
     * any reason, the node now detects and fixes it automatically instead
     * of getting stuck (peers won't recognize our locator, so they just
     * keep resending genesis, which we'd then reject as "doesn't chain,"
     * forever).
     */
    private void verifyGenesisOrReset() {
        int tip = db.getHeaderTip();
        if (tip < 0) return; // nothing stored yet, nothing to verify
        byte[] storedGenesis = db.getHeader(0);
        if (storedGenesis == null) return;
        byte[] computedHash = HeaderUtil.hash(storedGenesis);
        if (!Arrays.equals(computedHash, GENESIS_HASH)) {
            System.out.println("[ChainSync] Stored genesis header doesn't match the "
                    + "real network genesis hash -- performing a full database reset. "
                    + "This can happen if the data predates a fix, but can also mean "
                    + "the database file itself was left in an inconsistent state by "
                    + "an unclean shutdown (e.g. a forceful process kill while the "
                    + "node was still running) -- either way, resetting headers alone "
                    + "isn't safe here, since blocks/UTXOs/names derived from that same "
                    + "data could be equally suspect. No manual deletion needed.");
            System.out.println("[ChainSync] Computed hash: " + toHex(computedHash));
            System.out.println("[ChainSync] Expected hash: " + toHex(GENESIS_HASH));
            System.out.println("[ChainSync] Stored genesis header (hex): " + toHex(storedGenesis));
            db.fullReset();
        }
    }

    /**
     * Defensive startup check: verifies the stored header chain actually
     * links correctly at the tip (header[h].prevBlock really does equal
     * hash(header[h-1])), and that the block stored at the block tip (if
     * any) genuinely matches its own header. MVStore's own commit model
     * already makes true mid-write corruption very unlikely -- a commit
     * either fully lands or doesn't, there's no partial state -- but this
     * catches the remaining edge cases that model doesn't cover: a code
     * bug elsewhere, or storage hardware that doesn't honor fsync
     * properly.
     * <p>
     * A broken header link escalates to the same full reset as a genesis
     * mismatch, rather than a narrower trim: a break at the tip could
     * indicate the same kind of broader inconsistency (e.g. an unclean
     * shutdown), and this project has no reorg/undo mechanism for the
     * UTXO/name state changes already applied from blocks above wherever
     * a narrower trim would land. A block/header mismatch at just the
     * block tip is more isolated -- it doesn't call the headers
     * themselves into question -- so that gets a narrower, block-tip-only
     * rollback instead.
     */
    private void verifyTipConsistencyOrTrim() {
        int tip = db.getHeaderTip();
        if (tip >= 1) {
            byte[] current = db.getHeader(tip);
            byte[] prev = db.getHeader(tip - 1);
            boolean linksCorrectly = current != null && prev != null
                    && Arrays.equals(HeaderUtil.prevBlock(current), HeaderUtil.hash(prev));
            if (!linksCorrectly) {
                System.out.println("[ChainSync] Stored header chain doesn't link correctly "
                        + "at the tip -- performing a full database reset, for the same "
                        + "reason as a genesis mismatch: this can indicate a broader "
                        + "inconsistency, and this project has no way to safely undo "
                        + "UTXO/name changes already applied above a narrower trim point. "
                        + "No manual deletion needed.");
                db.fullReset();
                return; // nothing further to check against a database that was just wiped
            }
        }

        int blockTip = db.getBlockTip();
        if (blockTip >= 0) {
            byte[] header = db.getHeader(blockTip);
            byte[] block = db.getBlock(blockTip);
            boolean blockMatches = header != null && block != null && block.length >= 236
                    && Arrays.equals(Arrays.copyOf(block, 236), header);
            if (!blockMatches) {
                int newBlockTip = Math.min(blockTip - 1, db.getHeaderTip());
                System.out.printf("[ChainSync] Block at height %d doesn't match its own "
                        + "stored header -- resetting block tip to %d so it gets "
                        + "re-downloaded and re-validated.%n", blockTip, newBlockTip);
                db.setBlockTip(newBlockTip);
            }
        }
    }

    /**
     * Stops the sync scheduler -- and, critically, actually waits for
     * any already-in-progress syncCycle() execution to genuinely finish
     * before returning, not just for scheduler.shutdown() to prevent
     * future runs from being scheduled. Those are different things:
     * shutdown() alone let a real, observed shutdown proceed straight
     * to db.close()/ConfigDB.close() while a background cycle was still
     * mid-flight inside BlockProcessor, producing "Map is closed"/"This
     * store is closed" errors from the losing side of that race. The
     * errors themselves were caught cleanly (MVStore correctly refused
     * the post-close operation rather than corrupting anything, and the
     * failed write for that one height was never committed, so it will
     * simply be re-downloaded and reprocessed on the next start) --
     * but the race itself was real and worth actually closing, not just
     * relying on having gotten lucky with the timing this time.
     */
    public void stop() {
        running = false;
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(30, TimeUnit.SECONDS)) {
                System.out.println("[ChainSync] Sync cycle did not stop within 30s -- "
                        + "forcing shutdown (any in-flight block processing will be "
                        + "abandoned, safely: nothing partial gets committed).");
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scheduler.shutdownNow();
        }
    }

    // ── Main sync cycle ───────────────────────────────────────────────────────

    private void syncCycle() {
        if (!running) return;
        try {
            // Loop internally (fast, NOT gated by the 60-second scheduler
            // interval) as long as real progress is being made. This is
            // what lets syncHeaders() hand back control mid-sync (e.g. to
            // switch to a now-better-scored peer) without losing a full
            // minute waiting for the next scheduled tick -- reconnecting
            // happens immediately, and connectToBestPeer()'s weighted
            // selection naturally picks up the better peer using the
            // scores this same sync just updated.
            while (running) {
                int localTip = db.getHeaderTip();
                System.out.printf("[ChainSync] Tip: %d | Blocks: %d%n",
                        localTip, db.getBlockTip());

                List<PeerDiscovery.ConnectTarget> candidates =
                        PeerDiscovery.get().getCandidates();

                if (candidates.isEmpty()) {
                    System.out.println("[ChainSync] No peer candidates — retrying in "
                            + POLL_INTERVAL_SEC + "s.");
                    return;
                }

                // Try to connect to a peer for header sync
                PeerConnection peer = connectToBestPeer(candidates, localTip);
                if (peer == null) {
                    System.out.println("[ChainSync] No peers responded.");
                    return;
                }

                boolean madeProgress = false;
                try (peer) {
                    int peerHeight = peer.peerHeight;
                    System.out.printf("[ChainSync] Connected to %s (h=%d, agent=%s)%n",
                            peer.ip, peerHeight, peer.agent);

                    // Auto-rollback if we're far above all peers
                    if (localTip > peerHeight + 2016) {
                        System.out.printf("[ChainSync] Our tip %d >> peer %d — rolling back%n",
                                localTip, peerHeight);
                        db.resetHeaderTip(peerHeight);
                        localTip = peerHeight;
                    }

                    if (localTip < peerHeight) {
                        // Sync headers
                        int newTip = syncHeaders(peer, localTip, peerHeight);
                        System.out.printf("[ChainSync] Headers synced to %d%n", newTip);
                        madeProgress = newTip > localTip;
                    }

                    // Download missing blocks
                    downloadBlocks(peer);

                } catch (Exception e) {
                    PeerScorecard.get().recordFailure(peer.ip,
                            e.getClass().getSimpleName() + ": " + e.getMessage());
                    System.out.printf("[ChainSync] Peer %s error: %s%n",
                            peer.ip, e.getMessage());
                }

                // Fully caught up, or this round made no progress at all
                // (a connection/read error, an unresponsive peer, etc.) --
                // stop spinning and let the scheduler's next 60-second
                // tick check again, rather than busy-looping.
                if (!madeProgress) return;
            }

        } catch (Exception e) {
            System.err.println("[ChainSync] Cycle error: " + e.getMessage());
        }
    }

    // ── Peer connection ───────────────────────────────────────────────────────

    private PeerConnection connectToBestPeer(
            List<PeerDiscovery.ConnectTarget> candidates, int ourTip) {

        int maxPeerHeight = 0;
        String skipThisRound = avoidPeerIp;
        avoidPeerIp = null; // one-shot: consume it regardless of whether it was actually usable

        for (PeerDiscovery.ConnectTarget target : candidates) {
            if (!PeerScorecard.get().isGood(target.ip())) continue;
            if (target.ip().equals(skipThisRound)) continue;

            try {
                PeerConnection conn = connectPeer(target);
                if (conn == null) continue;

                maxPeerHeight = Math.max(maxPeerHeight, conn.peerHeight);
                connectedPeers.add(new PeerInfo(conn, System.currentTimeMillis(), false));

                if (conn.peerHeight >= ourTip) {
                    return conn; // good peer found
                }

                PeerScorecard.get().recordStaleTip(
                        target.ip(), conn.peerHeight, ourTip);
                System.out.printf("[ChainSync] Skipping %s (h=%d < our %d)%n",
                        target.ip(), conn.peerHeight, ourTip);
                conn.close();

            } catch (Exception e) {
                PeerScorecard.get().recordFailure(target.ip(),
                        e.getClass().getSimpleName() + ": " + e.getMessage());
                System.out.printf("[ChainSync] Connect to %s failed: %s: %s%n",
                        target.ip(), e.getClass().getSimpleName(), e.getMessage());
            }
        }

        // Auto-rollback if all peers are below us by a large margin
        if (maxPeerHeight > 0 && ourTip > maxPeerHeight + 2016) {
            System.out.printf("[ChainSync] All peers at ~%d, our tip %d — rolling back%n",
                    maxPeerHeight, ourTip);
            db.resetHeaderTip(maxPeerHeight);
        }

        // If diversification caused us to skip the one peer that would
        // otherwise have worked, fall back to trying it anyway rather
        // than stalling progress just to enforce variety -- avoidPeerIp
        // was already consumed above, so this retry naturally includes
        // every candidate.
        if (skipThisRound != null) {
            System.out.printf("[ChainSync] No other peer worked after skipping %s for "
                    + "diversification -- trying it again as a fallback.%n", skipThisRound);
            return connectToBestPeer(candidates, ourTip);
        }

        return null;
    }

    private PeerConnection connectPeer(PeerDiscovery.ConnectTarget target)
            throws Exception {
        if (!target.isBrontide()) return connectCleartextPeer(target);

        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(target.ip(), target.port()),
                CONNECT_TIMEOUT_MS);
        socket.setSoTimeout(HANDSHAKE_TIMEOUT);

        InputStream  in  = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        // Brontide handshake (initiator)
        BrontideState brontide = new BrontideState(
                identity.getPrivateKey(), target.brontideKey());

        // Act 1
        byte[] act1 = brontide.genActOne();
        if (VERBOSE_WIRE_LOGGING) {
            System.out.printf("[Handshake] -> %s Act1 (%d bytes): %s%n",
                    target.ip(), act1.length, toHex(act1));
            System.out.printf("[Handshake] DEBUG %s localEphemeralPriv=%s localStaticPriv=%s remoteStaticPub=%s%n",
                    target.ip(), toHex(brontide.debugLocalEphemeralPriv()),
                    toHex(identity.getPrivateKey()), toHex(target.brontideKey()));
        }
        out.write(act1);
        out.flush();

        // Act 2 -- read whatever comes back, even if incomplete, so we can
        // see exactly what (if anything) the peer sent before closing.
        byte[] act2 = readPartial(in, BrontideState.ACT_TWO_SIZE, target.ip());
        if (act2 == null || act2.length != BrontideState.ACT_TWO_SIZE) {
            throw new IOException("Incomplete Act 2");
        }
        if (VERBOSE_WIRE_LOGGING) {
            System.out.printf("[Handshake] <- %s Act2 (%d bytes): %s%n",
                    target.ip(), act2.length, toHex(act2));
        }
        brontide.recvActTwo(act2);

        // Act 3
        byte[] act3 = brontide.genActThree();
        if (VERBOSE_WIRE_LOGGING) {
            System.out.printf("[Handshake] -> %s Act3 (%d bytes): %s%n",
                    target.ip(), act3.length, toHex(act3));
        }
        out.write(act3);
        out.flush();

        socket.setSoTimeout(READ_TIMEOUT_MS);

        // P2P handshake
        PeerConnection conn = new PeerConnection(socket, in, out, brontide,
                target.ip());
        conn.doVersionHandshake(db.getBlockTip());

        // Request this peer's own peer table. Fire-and-forget rather than
        // blocking here for a response -- the ADDR reply (whenever it
        // arrives) gets picked up by handleNonBlockMessage during whatever
        // read loop runs next (header sync, block download, etc.), same
        // as any other incidental message.
        //
        // (Was temporarily disabled during an A/B test that suspected
        // GETADDR of interfering with GETHEADERS -- it wasn't the cause;
        // the real bug was a foundational error in Blake2b affecting
        // every block/header hash. Restored.)
        conn.sendMessage(MSG_GETADDR, new byte[0]);

        PeerScorecard.get().recordSuccess(target.ip(), conn.agent, conn.peerHeight, target.isBrontide());
        return conn;
    }

    /**
     * Connects to a peer with no known Brontide key, using cleartext P2P
     * on port 12038 -- no Noise/Act1-2-3 handshake at all, just the raw
     * magic+type+length framing directly over the socket. Reuses
     * PeerConnection's doVersionHandshake()/syncHeaders()/etc unchanged
     * (they don't care whether the transport is encrypted), by
     * constructing it with brontide=null, which sendMessage()/readMessage()
     * already branch on.
     */
    private PeerConnection connectCleartextPeer(PeerDiscovery.ConnectTarget target)
            throws Exception {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(target.ip(), target.port()),
                CONNECT_TIMEOUT_MS);
        socket.setSoTimeout(HANDSHAKE_TIMEOUT);

        InputStream  in  = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        PeerConnection conn = new PeerConnection(socket, in, out, null, target.ip());
        conn.doVersionHandshake(db.getBlockTip());

        conn.sendMessage(MSG_GETADDR, new byte[0]);

        PeerScorecard.get().recordSuccess(target.ip(), conn.agent, conn.peerHeight, false);
        return conn;
    }

    /**
     * Like readExact, but on early EOF or timeout returns whatever bytes
     * WERE received (possibly zero) instead of null/throwing, and logs
     * them -- so a partial or empty response is visible for debugging
     * instead of being collapsed into a generic "Incomplete Act 2".
     */
    private static byte[] readPartial(InputStream in, int len, String ip) {
        byte[] buf = new byte[len];
        int read = 0;
        try {
            while (read < len) {
                int n = in.read(buf, read, len - read);
                if (n < 0) break; // EOF
                read += n;
            }
        } catch (IOException e) {
            System.out.printf("[Handshake] <- %s read error after %d/%d bytes: %s: %s%n",
                    ip, read, len, e.getClass().getSimpleName(), e.getMessage());
        }
        if (read < len) {
            byte[] partial = Arrays.copyOf(buf, read);
            System.out.printf("[Handshake] <- %s only got %d/%d bytes: %s%n",
                    ip, read, len, read > 0 ? toHex(partial) : "(connection closed with zero bytes sent)");
            return null;
        }
        return buf;
    }

    private static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                default   -> sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // ── Header sync ───────────────────────────────────────────────────────────

    private int syncHeaders(PeerConnection peer, int localTip, int peerHeight)
            throws Exception {
        int tip = localTip;
        int batchesOnThisPeer = 0;

        while (tip < peerHeight && running) {
            // Build locator (sparse list of known block hashes)
            List<byte[]> locator = buildLocator(tip);

            // Send GETHEADERS
            long requestStart = System.currentTimeMillis();
            peer.sendGetHeaders(locator);

            // Receive HEADERS -- but real peers commonly send other
            // messages (SENDCMPCT, PING, etc.) around this point that
            // have nothing to do with our specific request. Previously
            // this read exactly one message and gave up entirely if it
            // wasn't HEADERS, silently treating any unrelated message as
            // "no more headers" -- the same class of bug just fixed in
            // doVersionHandshake. Loop past anything else instead, only
            // breaking on a genuine timeout or an actual empty HEADERS.
            byte[] msg = null;
            long deadline = System.currentTimeMillis() + 30_000;
            System.out.printf("[ChainSync] Waiting for HEADERS response from %s (up to 30s)...%n", peer.ip);
            while (System.currentTimeMillis() < deadline) {
                byte[] candidate = peer.readMessage(30_000);
                if (candidate == null) break;
                int type = getMessageType(candidate);
                if (type == MSG_HEADERS) {
                    msg = candidate;
                    break;
                } else {
                    handleNonBlockMessage(candidate, peer);
                }
                // Anything else (SENDCMPCT, INV, etc.) is handled by
                // handleNonBlockMessage above and the loop continues
                // waiting for HEADERS.
            }
            if (msg == null) {
                System.out.printf("[ChainSync] No HEADERS response from %s within 30s.%n", peer.ip);
                break;
            }
            PeerScorecard.get().recordLatency(peer.ip, System.currentTimeMillis() - requestStart);

            // Parse headers
            List<byte[]> headers = parseHeaders(msg);
            if (headers.isEmpty()) break;

            // Chain-link validation: each header's prevBlock must
            // correctly reference the previous header's hash. The prevBlock
            // offset (12) is now EMPIRICALLY CONFIRMED correct -- checked
            // directly against a real captured header whose prevBlock field
            // exactly matched the known genesis hash byte-for-byte at this
            // offset. Blocking again: stop accepting a batch at the first
            // broken link rather than storing headers we can't trust (this
            // is exactly the check that should have caught a peer
            // responding with headers that don't actually connect to our
            // real stored tip, instead of silently mis-storing them under
            // the wrong height labels).
            byte[] previousHeader = tip >= 0 ? db.getHeader(tip) : null;
            List<byte[]> validHeaders = new ArrayList<>();
            for (byte[] h : headers) {
                if (previousHeader != null && !HeaderUtil.chainsFrom(h, previousHeader)) {
                    PeerScorecard.get().recordInvalidData(peer.ip,
                            "header at height " + (tip + validHeaders.size() + 1)
                                    + " doesn't chain from previous header");
                    break;
                }
                // Proof-of-work check -- a much stronger signal than a
                // chain-link mismatch (which can happen for benign
                // reasons like a brief reorg). An honest, correctly-
                // functioning peer would never relay a header whose hash
                // doesn't satisfy its own claimed difficulty target, so
                // this is treated as a real, permanent ban rather than
                // just a scored/backed-off signal.
                if (!HeaderUtil.checkPOW(h)) {
                    PeerScorecard.get().banPeer(peer.ip,
                            "sent header at height " + (tip + validHeaders.size() + 1)
                                    + " with invalid proof-of-work");
                    break;
                }
                validHeaders.add(h);
                previousHeader = h;
            }
            if (validHeaders.isEmpty()) break;
            if (validHeaders.size() == headers.size()) {
                PeerScorecard.get().recordValidData(peer.ip);
            }

            // Store headers (with fake-header cap). Special case: the
            // very first batch of a fresh sync (tip started at -1) is
            // NOT actually height-0-onward data, even though tip+1=0
            // would suggest that -- buildLocator() deliberately sends
            // GENESIS_HASH as the locator when starting fresh (see its
            // own comment for why an empty locator doesn't work), which
            // tells the peer "I already have genesis," so the peer
            // correctly responds with headers starting at height 1, not
            // 0. Storing that response starting at height 0 shifted
            // every single height down by one and meant the real genesis
            // header was never stored at all -- explaining the
            // recurring "genesis hash doesn't match" resets, since
            // db.getHeader(0) was actually returning height 1's data.
            boolean isVeryFirstBatch = (localTip < 0 && tip == localTip);
            int insertStartHeight = isVeryFirstBatch ? 1 : tip + 1;
            if (isVeryFirstBatch) {
                db.insertHeaders(java.util.List.of(REAL_GENESIS_HEADER), 0);
            }
            db.insertHeaders(validHeaders, insertStartHeight);
            tip = db.getHeaderTip();

            System.out.printf("[ChainSync] Headers: %d/%d%n", tip, peerHeight);

            // After each batch, check whether a meaningfully better peer
            // has emerged (e.g. thanks to the latency/valid-data scoring
            // this batch just fed back in) -- if so, hand back control so
            // the caller can reconnect to it for the next batch, rather
            // than committing to this connection for the entire sync
            // regardless of how it's actually performing.
            batchesOnThisPeer++;
            if (shouldSwitchPeer(peer.ip)) {
                System.out.printf("[ChainSync] A better-scored peer than %s is now available -- "
                        + "switching for the next batch.%n", peer.ip);
                break;
            }
            // Periodic forced diversification: even a peer that's
            // performing perfectly well still shouldn't be relied on
            // indefinitely as the sole source of chain data -- score-
            // based switching alone tends toward a self-reinforcing
            // loop, since the currently-connected peer is the only one
            // actively earning fresh valid-data/latency points while
            // every other candidate's score just sits static. Rotating
            // periodically regardless of score both limits how much any
            // single peer (compromised or not) shapes our view of the
            // chain, and keeps other peers' scores exercised and
            // meaningful rather than perpetually stale.
            if (batchesOnThisPeer >= MAX_BATCHES_PER_PEER) {
                System.out.printf("[ChainSync] Rotating away from %s after %d batches "
                                + "(periodic diversification, not a score judgment).%n",
                        peer.ip, batchesOnThisPeer);
                avoidPeerIp = peer.ip;
                break;
            }
        }

        return tip;
    }

    /**
     * True if the current peer has fallen meaningfully behind the
     * top-ranked candidate in the scorecard -- a real, but not overly
     * twitchy, threshold, so a brief scoring fluctuation doesn't trigger
     * a reconnect on every single batch.
     */
    private boolean shouldSwitchPeer(String currentIp) {
        List<PeerScorecard.PeerRecord> ranked = PeerScorecard.get().getRankedPeers();
        if (ranked.isEmpty()) return false;
        int topScore = ranked.get(0).score;
        int currentScore = ranked.stream()
                .filter(r -> r.ip.equals(currentIp))
                .findFirst()
                .map(r -> r.score)
                .orElse(topScore); // if we're not even tracked yet, don't force a switch
        return !ranked.get(0).ip.equals(currentIp)
                && (topScore - currentScore) >= PEER_SWITCH_SCORE_MARGIN;
    }

    /**
     * Mainnet genesis block hash -- REAL block hash (Handshake's actual
     * "share hash" scheme, see HeaderUtil.hash()), verified byte-for-byte
     * against real hsd's own computed hash for this exact genesis header.
     * <p>
     * This is the THIRD value this constant has held, and the story is
     * worth keeping: the ORIGINAL constant (5b6ef2d3c1f3cdca...) was
     * genesis's own prevBlock sentinel, not a hash at all. The SECOND
     * value (43a0c70e...) was a real computed hash -- but computed with a
     * Blake2b implementation that had a foundational bug (10 rounds
     * instead of the required 12), discovered only by comparing every
     * intermediate step of the real share-hash algorithm against real
     * hsd's own output and independently against Python's hashlib. That
     * Blake2b bug affected every single block/header hash computed
     * throughout this entire project, and explains why no real peer ever
     * recognized our GETHEADERS locator no matter what else got fixed
     * along the way (wire format, nonce handling, message sequencing --
     * all correct the whole time, but built on a broken hash function).
     */
    /**
     * Real Handshake mainnet genesis hash. CORRECTED: the previous value
     * here (0000000000a5e40e8ba291bd7e8649747fa7fb8a7af39f5bacdb7433cd2f5971)
     * was simply wrong -- confirmed directly and authoritatively against
     * a real hsd installation's own "rpc getblockhash 0" output, which
     * returns 5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0
     * instead. Independently re-verified by running the real, matching
     * raw genesis header (below) through this project's own
     * HeaderUtil.hash() and confirming an exact match with that real
     * hsd output -- not just trusting either source alone.
     * <p>
     * This wrong value is what caused the recurring "genesis doesn't
     * match, full reset" cycle: it never matched anything a real chain
     * could ever produce, so verifyGenesisOrReset() failed unconditionally
     * on every single fresh sync, deterministically, not intermittently.
     */
    private static final byte[] GENESIS_HASH = {
            (byte)0x5b,(byte)0x6e,(byte)0xf2,(byte)0xd3,(byte)0xc1,(byte)0xf3,(byte)0xcd,(byte)0xca,
            (byte)0xdf,(byte)0xd9,(byte)0xa0,(byte)0x30,(byte)0xba,(byte)0x18,(byte)0x11,(byte)0xef,
            (byte)0xdd,(byte)0x17,(byte)0x74,(byte)0x0f,(byte)0x14,(byte)0xe1,(byte)0x66,(byte)0x48,
            (byte)0x97,(byte)0x60,(byte)0x74,(byte)0x1d,(byte)0x07,(byte)0x59,(byte)0x92,(byte)0xe0
    };

    /**
     * The real, complete 236-byte genesis header, needed alongside
     * GENESIS_HASH: buildLocator() sends GENESIS_HASH as the locator
     * when starting a fresh sync (see its own comment for why an empty
     * locator doesn't work), which correctly tells a real peer "I
     * already have genesis" -- meaning the peer's response starts at
     * height 1, not 0, and genesis itself is never sent to us at all.
     * This has to be inserted explicitly instead. Retrieved directly
     * from a real hsd installation via "rpc getblockheader
     * 5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0
     * false", and independently confirmed to hash to exactly
     * GENESIS_HASH via this project's own HeaderUtil.hash() before
     * being trusted here.
     */
    private static final byte[] REAL_GENESIS_HEADER = {
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x76,(byte)0x41,(byte)0x38,(byte)0x5e,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x1a,(byte)0x2c,(byte)0x60,(byte)0xb9,
            (byte)0x43,(byte)0x92,(byte)0x06,(byte)0x93,(byte)0x8f,(byte)0x8d,(byte)0x78,(byte)0x23,
            (byte)0x78,(byte)0x2a,(byte)0xbd,(byte)0xb8,(byte)0xb2,(byte)0x11,(byte)0xa5,(byte)0x74,
            (byte)0x31,(byte)0xe9,(byte)0xc9,(byte)0xb6,(byte)0xa6,(byte)0x36,(byte)0x5d,(byte)0x8d,
            (byte)0x42,(byte)0x89,(byte)0x33,(byte)0x51,(byte)0x8e,(byte)0x4c,(byte)0x97,(byte)0x56,
            (byte)0xfe,(byte)0xf2,(byte)0xad,(byte)0x10,(byte)0x37,(byte)0x5f,(byte)0x36,(byte)0x0e,
            (byte)0x05,(byte)0x60,(byte)0xfc,(byte)0xc7,(byte)0x58,(byte)0x7e,(byte)0xb5,(byte)0x22,
            (byte)0x3d,(byte)0xdf,(byte)0x8c,(byte)0xd7,(byte)0xc7,(byte)0xe0,(byte)0x6e,(byte)0x60,
            (byte)0xa1,(byte)0x14,(byte)0x0b,(byte)0x15,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0xff,(byte)0xff,(byte)0x00,(byte)0x1c,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
            (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
    };

    private List<byte[]> buildLocator(int tip) {
        List<byte[]> locator = new ArrayList<>();

        // On a fresh chain (no headers at all yet) there's nothing in the
        // DB to build a real locator from, so the loop below never runs
        // even once, and we'd send an empty locator with just a stop
        // hash. Real hsd peers apparently don't respond to that -- their
        // own client code always seeds the very first locator explicitly
        // with the genesis hash instead of leaving it empty.
        if (tip < 0) {
            locator.add(GENESIS_HASH);
            return locator;
        }

        int step = 1;
        for (int h = tip; h >= 0; h -= step) {
            byte[] header = db.getHeader(h);
            if (header != null) {
                locator.add(HeaderUtil.hash(header));
            }
            if (locator.size() > 10) step *= 2;
            if (locator.size() >= 32) break;
        }
        return locator;
    }

    private List<byte[]> parseHeaders(byte[] msg) {
        List<byte[]> headers = new ArrayList<>();
        try {
            int pos = 9; // skip frame header (magic+cmd+length)
            int count = (int) readVarint(msg, pos);
            pos += varintSize(count);
            // Confirmed directly against real hsd source (lib/primitives/
            // headers.js): Headers.write() calls ONLY writeHead(bw) -- the
            // raw 236-byte header, nothing else. No trailing tx-count byte
            // at all (that's a Block-specific concept; a Headers message
            // has no transactions to count). Headers are packed back-to-
            // back with nothing between them. The previous version here
            // incorrectly tried to skip a tx-count varint after every
            // header, which happened to consume the first byte(s) of the
            // NEXT header instead -- explaining exactly why only the
            // first header in any multi-header batch ever parsed
            // correctly; every one after that was read from a
            // byte-misaligned position and would almost always fail the
            // chain-link check.
            while (count-- > 0 && pos + 236 <= msg.length) {
                headers.add(Arrays.copyOfRange(msg, pos, pos + 236));
                pos += 236;
            }
        } catch (Exception ignored) {}
        return headers;
    }

    // ── Block download ────────────────────────────────────────────────────────

    private void downloadBlocks(PeerConnection peer) throws Exception {
        int headerTip = db.getHeaderTip();
        int blockTip  = db.getBlockTip();

        if (blockTip >= headerTip) return;

        System.out.printf("[ChainSync] Downloading blocks %d → %d%n",
                blockTip + 1, headerTip);

        int height = blockTip + 1;
        int blocksSinceCommit = 0;
        try {
            while (height <= headerTip && running) {
                // Request a batch of blocks
                int batchEnd = Math.min(height + MAX_BLOCK_BATCH - 1, headerTip);
                List<byte[]> hashes = new ArrayList<>();
                for (int h = height; h <= batchEnd; h++) {
                    byte[] header = db.getHeader(h);
                    if (header != null) hashes.add(HeaderUtil.hash(header));
                }

                peer.sendGetData(hashes, 2); // type 2 = BLOCK

                // Receive blocks
                int received = 0;
                while (received < hashes.size() && running) {
                    byte[] msg = peer.readMessage(60_000);
                    if (msg == null) break;
                    if (getMessageType(msg) != MSG_BLOCK) {
                        handleNonBlockMessage(msg, peer);
                        continue;
                    }
                    processBlock(msg, height + received, peer.ip);
                    received++;
                }

                height += received;
                blocksSinceCommit += received;

                // Commit periodically rather than after every single block
                // (BlockProcessor no longer does this itself -- see its own
                // comment for why unbatched per-block commits caused a
                // gradually worsening slowdown as the database grew, with no
                // error and no socket timeout since it wasn't actually stuck
                // on network I/O). Blocks carry far more data per item than
                // headers, so this batches less aggressively than the
                // 2000-per-commit used for header sync.
                if (blocksSinceCommit >= BLOCK_COMMIT_INTERVAL) {
                    db.commit();
                    // Bounded to a modest time budget so this can't stall
                    // active syncing for an unpredictable length of time --
                    // commit() alone only makes the current version durable,
                    // it doesn't reclaim disk space from old, superseded
                    // versions (that's what actually caused the database to
                    // balloon to 33GB for a much smaller real chain).
                    db.compact(1000);
                    blocksSinceCommit = 0;
                }

                if (received == 0) break;
            }
        } finally {
            // Guarantee whatever was accumulated gets committed even if
            // this exits via an exception (a real possibility -- network
            // errors, decrypt failures that throw rather than return
            // null) rather than the normal loop conditions. Without this,
            // moving to batched commits could actually make an
            // interruption LOSE MORE progress than the old per-block
            // behavior did, which would be a real regression.
            if (blocksSinceCommit > 0) db.commit();
        }
    }

    private void processBlock(byte[] msg, int height, String fromIp) {
        byte[] rawBlock = Arrays.copyOfRange(msg, 9, msg.length);
        byte[] header   = Arrays.copyOf(rawBlock, Math.min(236, rawBlock.length));
        byte[] hash     = HeaderUtil.hash(header);

        // Verify it matches our stored header
        byte[] storedHeader = db.getHeader(height);
        if (storedHeader != null) {
            byte[] storedHash = HeaderUtil.hash(storedHeader);
            if (!Arrays.equals(hash, storedHash)) {
                System.err.printf("[ChainSync] Block %d hash mismatch!%n", height);
                PeerScorecard.get().recordInvalidData(fromIp,
                        "block " + height + " hash mismatch");
                return;
            }
        }

        // Process transactions (UTXO + name state updates) BEFORE
        // committing this height as "done" -- if the merkle root doesn't
        // match, nothing about this height should be recorded as
        // downloaded, or it would never get re-requested (from this peer
        // or, ideally, a different one) and the UTXO/name-state database
        // would be permanently missing this height's changes.
        boolean blockValid = BlockProcessor.process(rawBlock, height, db, mempool);
        if (!blockValid) {
            // Reason is generic here since process() can now fail for
            // either a merkle root mismatch or a checked, failed
            // signature verification -- the specific reason is already
            // logged to the console by BlockProcessor itself at the
            // point of failure.
            PeerScorecard.get().banPeer(fromIp,
                    "sent block " + height + " that failed validation");
            return;
        }
        PeerScorecard.get().recordValidData(fromIp);

        // Store block
        db.saveBlock(rawBlock, height);
        db.setBlockTip(height);
        blocksDownloaded.incrementAndGet();
        lastBlockTime.set(System.currentTimeMillis());

        // Notify listeners (wallet app, DNS app)
        if (rpc != null) rpc.notifyNewBlock(height, hash, rawBlock);

        if (height % 100 == 0) {
            System.out.printf("[ChainSync] Block %d processed (total: %d)%n",
                    height, blocksDownloaded.get());
        }
    }

    private void handleNonBlockMessage(byte[] msg, PeerConnection peer)
            throws Exception {
        int type = getMessageType(msg);
        if (type == MSG_PING) {
            byte[] pingPayload = Arrays.copyOfRange(msg, 9, msg.length);
            peer.sendMessage(MSG_PONG, pingPayload);
        } else if (type == MSG_TX && mempool != null) {
            byte[] raw = Arrays.copyOfRange(msg, 9, msg.length);
            mempool.submitFromPeer(raw, peer.ip);
        } else if (type == MSG_ADDR) {
            PeerDiscovery.get().onAddrMessage(
                    Arrays.copyOfRange(msg, 9, msg.length), peer.ip);
        } else if (type == MSG_GETADDR) {
            peer.sendMessage(MSG_ADDR, buildAddrMessage());
        } else if (type == MSG_INV) {
            handleInv(peer, Arrays.copyOfRange(msg, 9, msg.length));
        }
        // Anything else (SENDCMPCT, etc.) is intentionally ignored here.
    }

    // ── RPC support ───────────────────────────────────────────────────────────

    public int getConnectedPeerCount() { return connectedPeers.size(); }

    public long inboundPeerCount() {
        return connectedPeers.stream().filter(PeerInfo::inbound).count();
    }

    public boolean isConnectedTo(String ip) {
        return connectedPeers.stream().anyMatch(p -> p.ip().equals(ip));
    }

    /**
     * Matches real hsd's getpeerinfo shape as closely as this project's
     * actual tracked data allows. Reads live values directly from each
     * PeerConnection (not a static snapshot taken at connect time), so
     * bytessent/bytesrecv/lastsend/lastrecv genuinely update as the
     * connection is used, not just reflect whatever was true the moment
     * it was accepted.
     * <p>
     * Still-honest gaps, left absent rather than fabricated: pingtime/
     * minping (no per-peer ping-RTT tracking exists), besthash (the
     * VERSION message this project's peers exchange doesn't carry a
     * hash, only a height), banscore (this project's PeerScorecard is a
     * different, positive-based reputation metric, not an accumulating
     * misbehavior counter -- not a clean 1:1 mapping), inflight (this
     * project doesn't pipeline multiple concurrent block requests per
     * connection), and whitelisted (no whitelist concept exists).
     */
    public String getPeerInfoJson() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        int id = 0;
        for (PeerInfo p : connectedPeers) {
            PeerConnection conn = p.conn();
            if (!first) sb.append(",");
            long connSeconds = (System.currentTimeMillis() - p.connTime()) / 1000;
            String addrLocal = conn.socket.getLocalSocketAddress() != null
                    ? conn.socket.getLocalSocketAddress().toString().replaceFirst("^/", "")
                    : "";
            sb.append("{")
                    .append("\"id\":").append(id++).append(",")
                    .append("\"addr\":\"").append(conn.ip).append(":").append(conn.socket.getPort()).append("\",")
                    .append("\"addrlocal\":\"").append(addrLocal).append("\",")
                    .append("\"name\":\"").append(conn.ip).append("\",")
                    .append("\"services\":\"").append(String.format("%08x", conn.services)).append("\",")
                    .append("\"lastsend\":").append(conn.lastSendTime).append(",")
                    .append("\"lastrecv\":").append(conn.lastRecvTime).append(",")
                    .append("\"bytessent\":").append(conn.bytesSent).append(",")
                    .append("\"bytesrecv\":").append(conn.bytesRecv).append(",")
                    .append("\"subver\":\"").append(jsonEscape(conn.agent)).append("\",")
                    .append("\"inbound\":").append(p.inbound()).append(",")
                    .append("\"startingheight\":").append(conn.peerHeight).append(",")
                    .append("\"bestheight\":").append(conn.peerHeight).append(",")
                    .append("\"conntime\":").append(connSeconds).append(",")
                    .append("\"timeoffset\":0,")
                    .append("\"version\":").append(conn.protocolVersion)
                    .append("}");
            first = false;
        }
        return sb.append("]").toString();
    }

    // ── Inbound connections ───────────────────────────────────────────────────
    //
    // P2PServer accepts the raw socket and completes the Brontide crypto
    // handshake (Act 1/2/3); this method takes over from there: the P2P
    // version handshake, then a background read loop for whatever the peer
    // sends unsolicited (PING, TX, GETADDR/ADDR, GETHEADERS, GETDATA).
    // Unlike outbound peers -- which connect, sync, and close within a
    // single syncCycle() -- inbound peers stay open until they disconnect
    // or the node shuts down, since we don't control when they'll have
    // something to say.

    private final ExecutorService inboundExecutor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "chain-sync-inbound");
        t.setDaemon(true);
        return t;
    });

    public void registerInboundPeer(Socket socket, BrontideState brontide, String ip) {
        try {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            PeerConnection conn = new PeerConnection(socket, in, out, brontide, ip);
            socket.setSoTimeout(HANDSHAKE_TIMEOUT);
            conn.doVersionHandshake(db.getBlockTip());
            socket.setSoTimeout(READ_TIMEOUT_MS);

            connectedPeers.add(new PeerInfo(conn, System.currentTimeMillis(), true));
            PeerScorecard.get().recordSuccess(ip, conn.agent, conn.peerHeight);

            inboundExecutor.submit(() -> runInboundLoop(conn));
        } catch (Exception e) {
            PeerScorecard.get().recordFailure(ip, "inbound handshake failed: " + e.getMessage());
            try { socket.close(); } catch (IOException ignored) { }
        }
    }

    private void runInboundLoop(PeerConnection conn) {
        try {
            while (running) {
                byte[] msg = conn.readMessage(300_000); // 5 min idle timeout
                if (msg == null) break;
                int type = getMessageType(msg);

                if (type == MSG_PING) {
                    byte[] pingPayload = Arrays.copyOfRange(msg, 9, msg.length);
                    conn.sendMessage(MSG_PONG, pingPayload);
                } else if (type == MSG_TX) {
                    if (mempool != null) {
                        mempool.submitFromPeer(Arrays.copyOfRange(msg, 9, msg.length), conn.ip);
                    }
                } else if (type == MSG_GETADDR) {
                    conn.sendMessage(MSG_ADDR, buildAddrMessage());
                } else if (type == MSG_ADDR) {
                    PeerDiscovery.get().onAddrMessage(Arrays.copyOfRange(msg, 9, msg.length), conn.ip);
                } else if (type == MSG_GETHEADERS) {
                    serveGetHeaders(conn, Arrays.copyOfRange(msg, 9, msg.length));
                } else if (type == MSG_GETDATA) {
                    serveGetData(conn, Arrays.copyOfRange(msg, 9, msg.length));
                } else if (type == MSG_INV) {
                    handleInv(conn, Arrays.copyOfRange(msg, 9, msg.length));
                }
            }
        } catch (Exception e) {
            // connection error or timeout; fall through to close
        } finally {
            conn.close();
        }
    }

    /**
     * Responds to a peer's unsolicited INV announcement (e.g. "here's a
     * new mempool transaction I have") by requesting anything we don't
     * already have via GETDATA. This is the receiving half of mempool
     * relay -- previously MSG_INV was completely unhandled in both
     * directions (never sent, never acted on), so even if a peer told us
     * about a new transaction, we'd silently ignore the announcement and
     * never actually fetch it.
     */
    private void handleInv(PeerConnection conn, byte[] payload) throws Exception {
        int pos = 0;
        int count = (int) readVarint(payload, pos);
        pos += varintSize(count);

        List<byte[]> toRequest = new ArrayList<>();
        for (int i = 0; i < count && pos + 36 <= payload.length; i++) {
            int itemType = (int) readLE32(payload, pos);
            byte[] hash = Arrays.copyOfRange(payload, pos + 4, pos + 36);
            pos += 36;
            if (itemType != 1) continue; // only TX announcements are handled here
            String txidHex = toHex(hash);
            if (mempool != null && mempool.getEntry(txidHex) == null) {
                toRequest.add(hash);
            }
        }
        if (!toRequest.isEmpty()) {
            conn.sendGetData(toRequest, 1); // type 1 = TX
        }
    }

    /**
     * Responds to a peer's GETHEADERS request -- the other half of what
     * this node has only ever done as a client (see syncHeaders()/
     * buildLocator()) until now. Finds the first locator hash we
     * recognize (locators are ordered most-recent-first, matching the
     * same convention our own outbound locators use), then sends up to
     * MAX_HEADERS_BATCH headers starting right after that point. Matches
     * the same wire format confirmed earlier this session for HEADERS
     * responses: headers packed back-to-back with no trailing byte
     * between them (that was the real bug behind the whole merkle-root
     * investigation days ago -- getting this format right here matters
     * just as much as it did on the receiving side).
     */
    private void serveGetHeaders(PeerConnection conn, byte[] payload) throws Exception {
        int pos = 0;
        int count = (int) readVarint(payload, pos);
        pos += varintSize(count);

        int matchHeight = -1; // -1 means "no match, start from genesis"
        for (int i = 0; i < count && pos + 32 <= payload.length; i++) {
            byte[] hash = Arrays.copyOfRange(payload, pos, pos + 32);
            pos += 32;
            if (matchHeight == -1) {
                int h = db.getHeightByHash(toHex(hash));
                if (h >= 0) matchHeight = h;
            }
        }
        // Stop hash (32 bytes) follows -- not enforced, matching this
        // node's own outbound requests, which always use an all-zero
        // stop hash and rely on the batch size cap instead.

        int startHeight = matchHeight + 1; // -1+1 = 0 (genesis) if no match
        int tip = db.getHeaderTip();
        if (startHeight > tip) {
            conn.sendMessage(MSG_HEADERS, new byte[]{0}); // empty response, varint(0)
            return;
        }

        int endHeight = Math.min(startHeight + MAX_HEADERS_BATCH - 1, tip);
        List<byte[]> toSend = new ArrayList<>();
        for (int h = startHeight; h <= endHeight; h++) {
            byte[] header = db.getHeader(h);
            if (header == null) break;
            toSend.add(header);
        }

        byte[] responsePayload = new byte[9 + toSend.size() * 236];
        int rpos = writeVarintBytes(responsePayload, 0, toSend.size());
        for (byte[] h : toSend) {
            System.arraycopy(h, 0, responsePayload, rpos, 236);
            rpos += 236;
        }
        conn.sendMessage(MSG_HEADERS, Arrays.copyOf(responsePayload, rpos));
    }

    /**
     * Responds to a peer's GETDATA request for blocks or mempool
     * transactions -- the other half of what this node has only ever
     * done as a client until now. Items we don't have are silently
     * skipped rather than answered with NOTFOUND; the requesting peer's
     * own timeout handles that case the same way ours already does.
     */
    private void serveGetData(PeerConnection conn, byte[] payload) throws Exception {
        int pos = 0;
        int count = (int) readVarint(payload, pos);
        pos += varintSize(count);

        for (int i = 0; i < count && pos + 36 <= payload.length; i++) {
            int itemType = (int) readLE32(payload, pos);
            byte[] hash = Arrays.copyOfRange(payload, pos + 4, pos + 36);
            pos += 36;
            String hashHex = toHex(hash);

            if (itemType == 2) { // BLOCK
                int height = db.getHeightByHash(hashHex);
                if (height < 0) continue;
                byte[] rawBlock = db.getBlock(height);
                if (rawBlock == null) continue; // header only, block not downloaded
                conn.sendMessage(MSG_BLOCK, rawBlock);
            } else if (itemType == 1 && mempool != null) { // TX
                byte[] rawTx = mempool.getRaw(hashHex);
                if (rawTx == null) continue;
                conn.sendMessage(MSG_TX, rawTx);
            }
        }
    }

    /** Builds an ADDR message payload (no frame wrapper -- sendMessage adds
     *  that) from currently-known peers, capped at 200 entries. Uses the
     *  real 88-byte NetAddress format (confirmed against real hsd source
     *  much earlier this session) -- this previously used a simplified
     *  30-byte-per-entry format with no room for a real key at all,
     *  meaning every peer we told others about was reported as keyless
     *  regardless of whether we actually knew its brontide key. */
    private byte[] buildAddrMessage() {
        List<PeerInfo> known = connectedPeers.subList(0, Math.min(200, connectedPeers.size()));
        byte[] payload = new byte[1 + known.size() * NET_ADDRESS_SIZE];
        int pos = 0;
        payload[pos++] = (byte) known.size();
        for (PeerInfo p : known) {
            SeedDatabase.Seed seed = SeedDatabase.get().getSeedByIp(p.ip());
            byte[] key = null;
            if (seed != null && seed.hasBrontideKey()) {
                key = NodeIdentity.base32Decode(seed.brontideKey());
            } else {
                String discoveredKey = PeerDiscovery.get().getBrontideKeyByIp(p.ip());
                if (discoveredKey != null) key = NodeIdentity.base32Decode(discoveredKey);
            }
            pos = writeNetAddressStatic(payload, pos, p.ip(), 44806, key);
        }
        return payload;
    }

    /** Shared NetAddress writer (real 88-byte format), usable both from
     *  PeerConnection (VERSION message) and here (ADDR message) without
     *  duplicating the field layout in two places. */
    private static int writeNetAddressStatic(byte[] buf, int pos, String ip, int port, byte[] brontideKey) {
        pos = writeLE64(buf, pos, 0L);   // time = 0
        pos = writeLE32(buf, pos, 0);    // services = 0
        pos = writeLE32(buf, pos, 0);    // hi_services = 0
        buf[pos++] = 0; // addr type (0 = IPv4)
        // raw[16]: standard IPv4-mapped IPv6 -- 10 zero bytes + 0xFF 0xFF + 4 IPv4 bytes
        pos += 10;
        buf[pos++] = (byte) 0xFF;
        buf[pos++] = (byte) 0xFF;
        String[] octets = ip.split("\\.");
        for (int i = 0; i < 4; i++) {
            buf[pos + i] = octets.length == 4 ? (byte) Integer.parseInt(octets[i]) : 0;
        }
        pos += 4;
        pos += 20; // reserved
        buf[pos++] = (byte) port;
        buf[pos++] = (byte) (port >> 8);
        if (brontideKey != null && brontideKey.length == 33) {
            System.arraycopy(brontideKey, 0, buf, pos, 33);
        } // else leave zeroed (matches a keyless/cleartext peer)
        pos += 33;
        return pos;
    }

    // ── PeerConnection ────────────────────────────────────────────────────────

    private class PeerConnection implements AutoCloseable {
        final Socket        socket;
        final InputStream   in;
        final OutputStream  out;
        final BrontideState brontide;
        final String        ip;
        volatile String     agent  = "";
        volatile int        peerHeight = 0;
        volatile int        protocolVersion = 0;
        volatile int        services = 0;
        volatile long       bytesSent = 0;
        volatile long       bytesRecv = 0;
        volatile long       lastSendTime = 0;
        volatile long       lastRecvTime = 0;

        PeerConnection(Socket socket, InputStream in, OutputStream out,
                       BrontideState brontide, String ip) {
            this.socket   = socket;
            this.in       = in;
            this.out      = out;
            this.brontide = brontide;
            this.ip       = ip;
        }

        void doVersionHandshake(int ourHeight) throws Exception {
            // Send VERSION
            sendVersion(ourHeight);

            // A proper handshake requires BOTH sides' VERSION and VERACK to
            // be exchanged before it's complete -- not just whichever one
            // happens to arrive first. Previously this broke out of the
            // loop the instant EITHER message type was seen, meaning if
            // the peer's VERACK arrived before their own VERSION message
            // (a very common ordering -- VERACK is typically sent in direct
            // reply to OUR VERSION, while THEIR VERSION arrives as a
            // separate, slightly later message), their VERSION message was
            // left unconsumed in the stream and got misread later by
            // whatever code issued the next request (GETHEADERS), which
            // then misinterpreted VERSION's bytes as if they were a
            // HEADERS response.
            boolean versionReceived = false;
            boolean verackReceived = false;
            long deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT;
            while (System.currentTimeMillis() < deadline) {
                if (versionReceived && verackReceived) break;
                byte[] msg = readMessage(HANDSHAKE_TIMEOUT);
                if (msg == null) throw new IOException("Handshake timeout");
                int type = getMessageType(msg);
                if (type == MSG_VERSION) {
                    parseVersion(Arrays.copyOfRange(msg, 9, msg.length));
                    sendMessage(MSG_VERACK, new byte[0]);
                    // (Was temporarily disabled during an A/B test that
                    // suspected this of interfering with GETHEADERS -- it
                    // wasn't the cause; the real bug was a foundational
                    // Blake2b error. Restored.)
                    sendMessage(MSG_SENDHEADERS, new byte[0]);
                    versionReceived = true;
                } else if (type == MSG_VERACK) {
                    verackReceived = true;
                }
                // Any other message type received during the handshake
                // window (PING, etc.) is simply ignored here and not
                // re-processed -- acceptable for now since real peers don't
                // typically send anything else this early.
            }
            if (!versionReceived || !verackReceived)
                throw new IOException("Handshake timeout (version="
                        + versionReceived + " verack=" + verackReceived + ")");
        }

        private void sendVersion(int ourHeight) throws Exception {
            // Real hsd VersionPacket layout, verified against a live hsd
            // installation: version(4) + services(4) + hi_services(4) +
            // time(8) + NetAddress(88) + nonce(8) + agentLen(1) + agent(N)
            // + height(4) + noRelay(1). Previously this sent a much
            // simpler, made-up layout with no NetAddress at all.
            //
            // ourHeight comes from ChainDB.getBlockTip(), which returns -1
            // to mean "no blocks yet" -- a valid internal sentinel, but
            // writeLE32(-1) serializes to 0xFFFFFFFF on the wire, which a
            // real peer reads back as an UNSIGNED height of 4,294,967,295.
            // Every single VERSION message sent so far had this exact
            // value; a real hsd node very plausibly rejects a peer
            // claiming a chain height of 4.29 billion outright. Clamp to 0
            // before it ever reaches the wire.
            if (ourHeight < 0) ourHeight = 0;
            byte[] agentBytes = userAgent().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] payload = new byte[4 + 4 + 4 + 8 + NET_ADDRESS_SIZE + 8 + 1 + agentBytes.length + 4 + 1];
            int pos = 0;
            pos = writeLE32(payload, pos, PROTOCOL_VERSION);
            pos = writeLE32(payload, pos, 1);           // services (ours)
            pos = writeLE32(payload, pos, 0);           // hi_services (always 0)
            pos = writeLE64(payload, pos, System.currentTimeMillis() / 1000);
            // NetAddress describes the REMOTE peer as we see it (the
            // Bitcoin-derived "addr_recv" convention), not our own address.
            // The real reference (HNSPeer.sendVersion) uses an all-zero key
            // here rather than the peer's actual brontide key -- matching
            // that exactly rather than my own guess, since this field
            // isn't otherwise verified against real behavior.
            pos = writeNetAddress(payload, pos, ip, socket.getPort(), new byte[33]);
            pos = writeLE64(payload, pos, 0L);           // nonce
            payload[pos++] = (byte) agentBytes.length;
            System.arraycopy(agentBytes, 0, payload, pos, agentBytes.length);
            pos += agentBytes.length;
            pos = writeLE32(payload, pos, ourHeight);
            payload[pos] = 0;                            // noRelay: 0 = please relay txs to us

            sendMessage(MSG_VERSION, payload);
        }

        /**
         * Real hsd NetAddress (88 bytes): time(8)+services(4)+hiServices(4)+
         * addrType(1)+raw(16)+reserved(20)+port(2)+key(33). Verified against
         * the real HNSMessage.java reference:
         *   - time/services/hi_services inside NetAddress are always 0
         *     (hardcoded, not the caller's current values) -- "we don't
         *     track when we last saw this peer"
         *   - raw[16] is the STANDARD IPv4-mapped-IPv6 format (10 zero
         *     bytes + 0xFF 0xFF + 4 IPv4 bytes), not "IPv4 + 12 zero bytes"
         *     as an earlier, less specific source had suggested
         */
        private int writeNetAddress(byte[] buf, int pos, String ip, int port, byte[] brontideKey) {
            return ChainSync.writeNetAddressStatic(buf, pos, ip, port, brontideKey);
        }

        private void parseVersion(byte[] msg) {
            try {
                // version(4) + services(4) + hi_services(4) + time(8) + NetAddress(88) + nonce(8) + agentLen(1) + agent(N) + height(4) + noRelay(1)
                if (msg.length >= 8) {
                    protocolVersion = (int) readLE32(msg, 0);
                    services = (int) readLE32(msg, 4);
                }
                int pos = 4 + 4 + 4 + 8 + NET_ADDRESS_SIZE + 8; // = 116, start of agentLen
                if (msg.length <= pos) return;
                int agentLen = msg[pos] & 0xFF;
                pos++;
                if (msg.length >= pos + agentLen) {
                    agent = new String(msg, pos, agentLen, java.nio.charset.StandardCharsets.UTF_8);
                    pos += agentLen;
                }
                if (msg.length >= pos + 4) {
                    peerHeight = (int) readLE32(msg, pos);
                    if (peerHeight > bestKnownPeerHeight) bestKnownPeerHeight = peerHeight;
                }
            } catch (Exception ignored) {}
        }

        void sendGetHeaders(List<byte[]> locator) throws Exception {
            // GETHEADERS payload: locator_count(varint) + hashes[] + stop_hash(32)
            // Confirmed directly against real hsd source (lib/net/packets.js,
            // GetHeadersPacket.write(), inherited from GetBlocksPacket): NO
            // leading version field. An earlier attempt to add one, based on
            // a secondary reference that turned out to be wrong here (the
            // same reference that had ACT_THREE_SIZE wrong), made things
            // worse -- it shifted every subsequent byte by 4, so the peer
            // went from "misinterprets a wrong hash" to "can't parse the
            // message at all," explaining the new "no response" symptom.
            byte[] payload = new byte[9 + locator.size() * 32 + 32];
            int pos = writeVarintBytes(payload, 0, locator.size());
            for (byte[] hash : locator) {
                System.arraycopy(hash, 0, payload, pos, 32);
                pos += 32;
            }
            // Stop hash = all zeros (get as many as possible)
            pos += 32;
            sendMessage(MSG_GETHEADERS, Arrays.copyOf(payload, pos));
        }

        void sendGetData(List<byte[]> hashes, int itemType) throws Exception {
            byte[] payload = new byte[9 + hashes.size() * 36];
            int pos = writeVarintBytes(payload, 0, hashes.size());
            for (byte[] hash : hashes) {
                pos = writeLE32(payload, pos, itemType);
                System.arraycopy(hash, 0, payload, pos, 32);
                pos += 32;
            }
            sendMessage(MSG_GETDATA, Arrays.copyOf(payload, pos));
        }

        /**
         * Sends a message using hsd's real frame format: magic(4 LE) +
         * cmd(1) + length(4 LE) + payload(N). If this is a Brontide
         * connection the frame is then encrypted; for a cleartext
         * connection (brontide == null) the frame is written directly --
         * the logical frame format is identical either way, only the
         * wire transport differs.
         */
        void sendMessage(int type, byte[] payload) throws Exception {
            byte[] frame = new byte[9 + payload.length];
            writeLE32(frame, 0, MAGIC_MAINNET);
            frame[4] = (byte) type;
            writeLE32(frame, 5, payload.length);
            System.arraycopy(payload, 0, frame, 9, payload.length);

            if (brontide == null) {
                if (VERBOSE_WIRE_LOGGING) {
                    System.out.printf("[Handshake] -> %s (cleartext) SEND type=%d frame(%d bytes): %s%n",
                            ip, type, frame.length, toHex(frame));
                }
                synchronized (out) {
                    out.write(frame);
                    out.flush();
                }
                totalBytesSent.addAndGet(frame.length);
                bytesSent += frame.length;
                lastSendTime = System.currentTimeMillis() / 1000;
                return;
            }

            byte[] encrypted = brontide.encryptMessage(frame);
            if (VERBOSE_WIRE_LOGGING) {
                System.out.printf("[Handshake] -> %s SEND type=%d frame(%d bytes): %s%n",
                        ip, type, frame.length, toHex(frame));
                System.out.printf("[Handshake] -> %s encrypted wire (%d bytes): %s%n",
                        ip, encrypted.length, toHex(encrypted));
            }
            synchronized (out) {
                out.write(encrypted);
                out.flush();
            }
            totalBytesSent.addAndGet(encrypted.length);
            bytesSent += encrypted.length;
            lastSendTime = System.currentTimeMillis() / 1000;
        }

        /**
         * Reads one message, returning the full frame (magic+cmd+length+
         * payload) with the magic number validated. For a cleartext
         * connection the frame is read directly off the wire; for
         * Brontide it's decrypted first. Either way the returned frame
         * format is identical, so getMessageType()/message handlers work
         * unchanged regardless of which transport this connection uses.
         * <p>
         * Verbose about exactly what comes back (byte counts, raw hex,
         * decrypted length) rather than collapsing everything to null --
         * this is what actually let the other conversation find its real
         * bugs (e.g. "Got 20 header bytes, Decrypted header, bodyLen=..."
         * revealing a tag-passes-but-garbage-output bug). A bare "timeout"
         * or "null" hides exactly the information needed to diagnose this.
         */
        byte[] readMessage(int timeoutMs) throws Exception {
            byte[] result = readMessageInternal(timeoutMs);
            if (result != null) {
                bytesRecv += result.length;
                lastRecvTime = System.currentTimeMillis() / 1000;
            }
            return result;
        }

        private byte[] readMessageInternal(int timeoutMs) throws Exception {
            socket.setSoTimeout(timeoutMs);

            if (brontide == null) {
                byte[] frame = readPartialDebug(in, 9, ip, "cleartext header");
                if (frame == null) return null;
                long magic = readLE32(frame, 0) & 0xFFFFFFFFL;
                if (magic != (MAGIC_MAINNET & 0xFFFFFFFFL)) {
                    System.out.printf("[Handshake] <- %s (cleartext) bad magic: 0x%08X%n", ip, magic);
                    return null;
                }
                int payloadLen = (int) readLE32(frame, 5);
                if (payloadLen < 0 || payloadLen > 4_000_000) return null;
                if (payloadLen == 0) return frame;
                byte[] payload = readPartialDebug(in, payloadLen, ip, "cleartext payload");
                if (payload == null) return null;
                byte[] full = new byte[9 + payloadLen];
                System.arraycopy(frame, 0, full, 0, 9);
                System.arraycopy(payload, 0, full, 9, payloadLen);
                return full;
            }

            byte[] header = readPartialDebug(in, 20, ip, "header");
            if (header == null) return null;

            int msgLen;
            try {
                msgLen = brontide.decryptLength(header);
            } catch (Exception e) {
                System.out.printf("[Handshake] <- %s header decrypt failed (tag/MAC check): %s: %s%n",
                        ip, e.getClass().getSimpleName(), e.getMessage());
                return null;
            }
            if (VERBOSE_WIRE_LOGGING) {
                System.out.printf("[Handshake] <- %s header decrypted OK, msgLen=%d%n", ip, msgLen);
            }
            if (msgLen < 0 || msgLen > 4_000_000) {
                System.out.printf("[Handshake] <- %s msgLen out of range, treating as invalid%n", ip);
                return null;
            }

            byte[] encPayload = readPartialDebug(in, msgLen + 16, ip, "payload");
            if (encPayload == null) return null;

            byte[] frame;
            try {
                frame = brontide.decryptPayload(encPayload);
            } catch (Exception e) {
                System.out.printf("[Handshake] <- %s payload decrypt failed (tag/MAC check): %s: %s%n",
                        ip, e.getClass().getSimpleName(), e.getMessage());
                return null;
            }
            if (frame == null || frame.length < 9) {
                System.out.printf("[Handshake] <- %s frame too short after decrypt: %d bytes%n",
                        ip, frame == null ? -1 : frame.length);
                return null;
            }
            long magic = readLE32(frame, 0) & 0xFFFFFFFFL;
            if (VERBOSE_WIRE_LOGGING) {
                System.out.printf("[Handshake] <- %s decrypted frame (%d bytes): %s%n",
                        ip, frame.length, toHex(frame));
            }
            if (magic != (MAGIC_MAINNET & 0xFFFFFFFFL)) {
                System.out.printf("[Handshake] <- %s bad magic: 0x%08X expected 0x%08X%n",
                        ip, magic, MAGIC_MAINNET & 0xFFFFFFFFL);
                return null;
            }
            return frame;
        }

        /**
         * Like readExact, but on early EOF returns null while logging
         * exactly how many bytes (if any) were received and their hex,
         * instead of silently collapsing a partial read into nothing.
         */
        private static byte[] readPartialDebug(InputStream in, int len, String ip, String label) {
            byte[] buf = new byte[len];
            int read = 0;
            try {
                while (read < len) {
                    int n = in.read(buf, read, len - read);
                    if (n < 0) break;
                    read += n;
                }
            } catch (IOException e) {
                totalBytesRecv.addAndGet(read);
                System.out.printf("[Handshake] <- %s %s read error after %d/%d bytes: %s: %s%n",
                        ip, label, read, len, e.getClass().getSimpleName(), e.getMessage());
                return null;
            }
            totalBytesRecv.addAndGet(read);
            if (read < len) {
                System.out.printf("[Handshake] <- %s %s: only got %d/%d bytes: %s%n",
                        ip, label, read, len,
                        read > 0 ? toHex(Arrays.copyOf(buf, read)) : "(connection closed with zero bytes)");
                return null;
            }
            return buf;
        }

        @Override
        public void close() {
            try { socket.close(); } catch (IOException ignored) {}
            connectedPeers.removeIf(p -> p.ip().equals(ip));
        }
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static byte[] readExact(InputStream in, int len) throws IOException {
        byte[] buf = new byte[len];
        int read = 0;
        while (read < len) {
            int n = in.read(buf, read, len - read);
            if (n < 0) return null;
            read += n;
        }
        return buf;
    }

    /** Reads the cmd byte at offset 4 of a frame (magic[0..3], cmd[4], length[5..8], payload[9..]). */
    private static int getMessageType(byte[] msg) {
        if (msg == null || msg.length < 9) return -1;
        return msg[4] & 0xFF;
    }

    private static long readLE32(byte[] b, int pos) {
        return (b[pos] & 0xFFL) | ((b[pos+1] & 0xFFL) << 8)
                | ((b[pos+2] & 0xFFL) << 16) | ((b[pos+3] & 0xFFL) << 24);
    }

    private static int writeLE32(byte[] b, int pos, long v) {
        b[pos]   = (byte) v;   b[pos+1] = (byte)(v>>8);
        b[pos+2] = (byte)(v>>16); b[pos+3] = (byte)(v>>24);
        return pos + 4;
    }

    private static int writeLE64(byte[] b, int pos, long v) {
        for (int i = 0; i < 8; i++) b[pos+i] = (byte)(v >> (i*8));
        return pos + 8;
    }

    private static long readVarint(byte[] b, int pos) {
        int first = b[pos] & 0xFF;
        if (first < 0xFD) return first;
        if (first == 0xFD) return readLE32(b, pos+1) & 0xFFFF;
        return readLE32(b, pos+1);
    }

    private static int varintSize(int v) {
        if (v < 0xFD) return 1;
        if (v <= 0xFFFF) return 3;
        return 5;
    }

    private static int writeVarintBytes(byte[] b, int pos, int v) {
        if (v < 0xFD) { b[pos] = (byte) v; return pos + 1; }
        b[pos] = (byte) 0xFD; b[pos+1] = (byte) v; b[pos+2] = (byte)(v>>8);
        return pos + 3;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}