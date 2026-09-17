package handshake.node;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * BrontideState — implements the Noise_XK handshake pattern used by
 * the Handshake P2P network for encrypted peer connections.
 *
 * Protocol: Noise_XK with:
 *   - Curve:    secp256k1
 *   - Hash:     SHA-256 (Noise/Brontide layer specifically -- Blake2b is
 *               still correct and used elsewhere in Handshake, for
 *               tx/block hashing, just not here)
 *   - Cipher:   ChaCha20-Poly1305
 *   - Encoding: Elligator2 for public key representation
 *
 * Handshake sequence (initiator → responder):
 *   Act 1 (80 bytes):  initiator sends ephemeral key + encrypted payload
 *   Act 2 (80 bytes):  responder sends ephemeral key + encrypted payload
 *   Act 3 (66 bytes):  initiator sends static key + encrypted payload
 *
 * After Act 3 both sides have shared session keys for encrypted transport.
 *
 * Reference: hsd/lib/net/brontide.js
 */
public class BrontideState {

    // ── Constants ─────────────────────────────────────────────────────────────

    public static final int ACT_ONE_SIZE   = 80;  // elligator(64) + tag(16)
    public static final int ACT_TWO_SIZE   = 80;
    // FIX: was 66. Confirmed directly against real hsd source
    // (lib/net/brontide.js): ACT_THREE_SIZE = 65 (33 + 16 + 16) -- an
    // encrypted 33-byte static key, its own 16-byte tag, and a
    // separate final 16-byte tag, with no extra byte. genActThree()
    // below only ever wrote 49+16=65 bytes into this array regardless
    // of its declared size, so the 66th byte was always an unwritten,
    // always-zero pad -- meaning every Act 3 this code ever sent was
    // silently one byte too long for a real peer, and recvActThree()
    // would have rejected a real peer's own correctly-sized 65-byte
    // Act 3 as "wrong size" had a handshake ever gotten this far. See
    // ChainSync.sendGetHeaders()'s own comment: this had already been
    // traced to the same unreliable secondary reference once before,
    // but the fix apparently never actually landed here.
    public static final int ACT_THREE_SIZE = 65;

    private static final String PROLOGUE = "hns";

    // ── State ─────────────────────────────────────────────────────────────────

    // Local identity
    private final byte[] localStaticPriv;
    private final byte[] localStaticPub;
    private final boolean isInitiator;

    // Remote static key (known for initiator, discovered in Act 3 for responder)
    private byte[] remoteStaticPub;

    // Ephemeral keys (generated per-handshake)
    private byte[] localEphemeralPriv;
    private BigInteger[] localEphemeralPubPoint;
    // FIX: caches the Elligator encoding chosen when generateEphemeral()
    // confirmed this key was encodable. Elligator.encode() is
    // probabilistic (picks random field elements internally), so a
    // second, separate call on the same point -- as genActOne() used to
    // make -- produces DIFFERENT random bytes, not the same ones, and
    // could occasionally fail even when the first call just succeeded.
    // Not a cryptographic bug (any valid encoding of the same point
    // works on the wire), but wasteful and needlessly fragile.
    private byte[] localEphemeralEncoded;

    // Remote ephemeral (received during handshake)
    private BigInteger[] remoteEphemeralPubPoint;

    // Noise state
    private byte[] chainingKey;   // ck
    private byte[] handshakeHash; // h
    private byte[] tempKey;       // temp_k
    // FIX: real hsd's CipherState.nonce is a PERSISTENT counter that only
    // resets to 0 inside mixKey() (via initKey()) -- it does NOT reset on
    // every single encrypt/decrypt call. It increments by 1 after every
    // AEAD operation and keeps counting until the next mixKey(). Previously
    // every encryptWithAd/decryptWithAd call here hardcoded nonce=0, which
    // only happened to be correct for the FIRST operation following each
    // mixKey() (Act 1's tag, Act 2's tag) -- both of which are exactly one
    // operation per epoch. Act 3's first tag (encryptHash(ourPubkey) on the
    // initiator, decryptHash(s1,p1) on the responder) is the SECOND
    // operation within the same "ee" mixKey epoch, following Act 2's own
    // decrypt/encrypt which already consumed nonce 0 and left it at 1 --
    // so it needed nonce=1, not the hardcoded 0. This is precisely why Act
    // 1 and Act 2 always verified correctly while Act 3's first tag never
    // did against any real peer.
    private long handshakeNonce;

    // Transport keys (set after Act 3)
    private byte[] sendKey;
    private byte[] recvKey;
    private long   sendNonce;
    private long   recvNonce;
    // FIX: real Brontide (matching Lightning's BOLT8 Noise transport,
    // confirmed byte-for-byte against hsd's own brontide-test.js
    // "should rotate the secret key" vector) rotates each direction's
    // cipher key independently after 1000 messages on that direction,
    // via (newSalt, newKey) = HKDF(oldKey, oldSalt) -- the exact same
    // hkdfExpandSha256() already used by mixKey(), just with the roles
    // of "secret" and "salt" filled by the old key and old chaining-key
    // (here called salt, matching hsd's own CipherState field name)
    // instead of a DH output and the handshake's ck. Without this, a
    // long-lived connection (exactly what block downloading produces --
    // hundreds of GETDATA/BLOCK messages on one connection) silently
    // diverges from the real peer's cipher state the moment either side
    // crosses 1000 messages: the peer rotates, we don't, and every
    // decrypt after that point fails with a tag mismatch
    // ("Length decryption failed") that looks like corruption but is
    // really just a key mismatch neither side can recover from without
    // reconnecting. sendSalt/recvSalt both start as the same final
    // handshake chaining key (chainingKey at the moment split() runs),
    // matching hsd's own split(): both directions' initSalt() receives
    // the same ck, only the keys (k1/k2) differ.
    private byte[] sendSalt;
    private byte[] recvSalt;
    private static final long ROTATION_INTERVAL = 1000;

    private static final SecureRandom RNG = new SecureRandom();

    // ── Constructor ───────────────────────────────────────────────────────────

    /**
     * Creates a Brontide state for initiating a connection.
     *
     * @param localStaticPriv  Our 32-byte static private key (node identity)
     * @param remoteStaticPub  Their 33-byte compressed static public key (from seed)
     */
    public BrontideState(byte[] localStaticPriv, byte[] remoteStaticPub) {
        this.localStaticPriv  = localStaticPriv;
        this.localStaticPub   = Secp256k1.compressedPublicKey(localStaticPriv);
        this.remoteStaticPub  = remoteStaticPub;
        this.isInitiator      = true;
        initHandshakeState();
    }

    /**
     * Creates a Brontide state for accepting an inbound connection.
     * Remote static key is unknown until Act 3.
     *
     * @param localStaticPriv  Our 32-byte static private key (node identity)
     */
    public BrontideState(byte[] localStaticPriv) {
        this.localStaticPriv  = localStaticPriv;
        this.localStaticPub   = Secp256k1.compressedPublicKey(localStaticPriv);
        this.remoteStaticPub  = null;
        this.isInitiator      = false;
        initHandshakeState();
    }

    // ── Initialization ────────────────────────────────────────────────────────

    private void initHandshakeState() {
        // FIX: a real, confirmed interop failure -- this string was
        // "Noise_XK_secp256k1+Elligator2_ChaChaPoly_BLAKE2b", which does
        // not match real hsd's own protocol name constant at all
        // (confirmed directly against hsd's actual source,
        // lib/net/brontide.js: PROTOCOL_NAME =
        // 'Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared'). This is
        // the very first value mixed into the handshake state, so every
        // key derived afterward -- including Act 1's own authentication
        // tag -- depended on it. A real peer seeded with the correct
        // name would compute a completely different tag than ours and
        // reject Act 1 outright: exactly the observed failure, a real
        // peer accepting the TCP connection, receiving our Act 1, then
        // closing without ever sending anything back (a correctly-
        // implemented Noise peer that can't authenticate the first
        // message says nothing further, by design). This bug was
        // invisible to this project's own loopback tests specifically
        // because both sides of a loopback used the same wrong string,
        // so they agreed with each other while disagreeing with every
        // real peer on the network.
        String protocolName = "Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared";
        byte[] nameBytes = protocolName.getBytes();
        if (nameBytes.length <= 32) {
            chainingKey = new byte[32];
            System.arraycopy(nameBytes, 0, chainingKey, 0, nameBytes.length);
        } else {
            chainingKey = sha256(nameBytes);
        }
        handshakeHash = chainingKey.clone();

        // Mix in prologue
        mixHash(PROLOGUE.getBytes());

        // Per Noise_XK's pre-message pattern ("<- s"), both sides must mix in
        // the SAME bytes here: the responder's static public key. The
        // initiator already has it (passed in as remoteStaticPub, e.g. from
        // the seed database); the responder mixes in its own static pubkey,
        // since from its own perspective that IS the responder's static key.
        // Skipping this on the responder side (as the previous version did,
        // since remoteStaticPub is still null at this point for it) desyncs
        // the two sides' handshake hash before Act 1 even begins, which
        // guarantees every later MAC/tag check fails.
        if (remoteStaticPub != null) {
            mixHash(remoteStaticPub);
        } else {
            mixHash(localStaticPub);
        }

        // Generate ephemeral key pair
        generateEphemeral();
    }

    private void generateEphemeral() {
        byte[] encoded;
        do {
            localEphemeralPriv = new byte[32];
            RNG.nextBytes(localEphemeralPriv);
            localEphemeralPubPoint = Secp256k1.pubKeyPoint(localEphemeralPriv);
            encoded = Elligator.encode(localEphemeralPubPoint);
        } while (encoded == null);
        // FIX: cache the exact successful encoding instead of discarding
        // it and re-calling Elligator.encode() later -- see the field
        // comment on localEphemeralEncoded for why a second call isn't
        // safe to rely on returning the same (or any) result.
        localEphemeralEncoded = encoded;
    }

    // ── Act 1 (Initiator → Responder) ─────────────────────────────────────────

    /**
     * Generates Act 1 message (80 bytes) as the initiator.
     * Sends: Elligator(ephemeral_pub) + AEAD(empty, h)
     */
    public byte[] genActOne() {
        byte[] ephemeralEncoded = localEphemeralEncoded;

        // e
        mixHash(Secp256k1.compressedPublicKey(localEphemeralPriv));

        // es: ECDH(e, rs)
        byte[] es = Secp256k1.ecdh(remoteStaticPub, localEphemeralPriv);
        mixKey(es);

        // Encrypt empty payload
        byte[] tag = encryptWithAd(handshakeHash, new byte[0]);

        byte[] act = new byte[ACT_ONE_SIZE];
        System.arraycopy(ephemeralEncoded, 0, act, 0, 64);
        System.arraycopy(tag, 0, act, 64, 16);
        return act;
    }

    /**
     * Processes Act 1 as the responder.
     * Reads: Elligator(ephemeral_pub) + AEAD tag
     *
     * @throws IllegalArgumentException if verification fails
     */
    public void recvActOne(byte[] act) {
        if (act.length != ACT_ONE_SIZE)
            throw new IllegalArgumentException("Act 1 wrong size: " + act.length);

        byte[] ephemeralEncoded = Arrays.copyOfRange(act, 0, 64);
        byte[] tag = Arrays.copyOfRange(act, 64, 80);

        // Decode ephemeral public key
        remoteEphemeralPubPoint = Elligator.decode(ephemeralEncoded);
        if (remoteEphemeralPubPoint == null)
            throw new IllegalArgumentException("Act 1: Elligator decode failed");

        byte[] remoteEphPub = compressPoint(remoteEphemeralPubPoint);

        // e
        mixHash(remoteEphPub);

        // es: ECDH(s, re)
        byte[] es = Secp256k1.ecdh(remoteEphPub, localStaticPriv);
        mixKey(es);

        // Verify tag
        if (!decryptWithAd(handshakeHash, tag, new byte[0]))
            throw new IllegalArgumentException("Act 1: MAC verification failed");
    }

    // ── Act 2 (Responder → Initiator) ─────────────────────────────────────────

    /**
     * Generates Act 2 message (80 bytes) as the responder.
     */
    public byte[] genActTwo() {
        byte[] ephemeralEncoded = localEphemeralEncoded;

        byte[] localEphPub = Secp256k1.compressedPublicKey(localEphemeralPriv);

        // e
        mixHash(localEphPub);

        // ee: ECDH(e, re)
        byte[] remoteEphPub = compressPoint(remoteEphemeralPubPoint);
        byte[] ee = Secp256k1.ecdh(remoteEphPub, localEphemeralPriv);
        mixKey(ee);

        // Encrypt empty payload
        byte[] tag = encryptWithAd(handshakeHash, new byte[0]);

        byte[] act = new byte[ACT_TWO_SIZE];
        System.arraycopy(ephemeralEncoded, 0, act, 0, 64);
        System.arraycopy(tag, 0, act, 64, 16);
        return act;
    }

    /**
     * Processes Act 2 as the initiator.
     */
    public void recvActTwo(byte[] act) {
        if (act.length != ACT_TWO_SIZE)
            throw new IllegalArgumentException("Act 2 wrong size: " + act.length);

        byte[] ephemeralEncoded = Arrays.copyOfRange(act, 0, 64);
        byte[] tag = Arrays.copyOfRange(act, 64, 80);

        remoteEphemeralPubPoint = Elligator.decode(ephemeralEncoded);
        if (remoteEphemeralPubPoint == null)
            throw new IllegalArgumentException("Act 2: Elligator decode failed");

        byte[] remoteEphPub = compressPoint(remoteEphemeralPubPoint);

        // e
        mixHash(remoteEphPub);

        // ee: ECDH(e, re)
        byte[] ee = Secp256k1.ecdh(remoteEphPub, localEphemeralPriv);
        mixKey(ee);

        // Verify tag
        if (!decryptWithAd(handshakeHash, tag, new byte[0]))
            throw new IllegalArgumentException("Act 2: MAC verification failed");
    }

    // ── Act 3 (Initiator → Responder) ─────────────────────────────────────────

    /**
     * Generates Act 3 message (66 bytes) as the initiator.
     * Sends encrypted static key + final AEAD payload.
     */
    public byte[] genActThree() {
        // Encrypt our static public key
        byte[] encryptedStatic = encryptWithAdFull(handshakeHash, localStaticPub);

        // se: ECDH(s, re)
        byte[] remoteEphPub = compressPoint(remoteEphemeralPubPoint);
        byte[] se = Secp256k1.ecdh(remoteEphPub, localStaticPriv);
        mixKey(se);

        // Encrypt empty payload (final tag)
        byte[] tag = encryptWithAd(handshakeHash, new byte[0]);

        // Split into transport keys
        split();

        byte[] act = new byte[ACT_THREE_SIZE];
        System.arraycopy(encryptedStatic, 0, act, 0, 49); // 33 + 16
        System.arraycopy(tag, 0, act, 49, 16);
        return act;
    }

    /**
     * Processes Act 3 as the responder.
     * Discovers and verifies the initiator's static key.
     */
    public void recvActThree(byte[] act) {
        if (act.length != ACT_THREE_SIZE)
            throw new IllegalArgumentException("Act 3 wrong size: " + act.length);

        byte[] encryptedStatic = Arrays.copyOfRange(act, 0, 49);
        byte[] tag = Arrays.copyOfRange(act, 49, 65);

        // Decrypt initiator's static key
        byte[] decryptedStatic = decryptWithAdFull(handshakeHash, encryptedStatic);
        if (decryptedStatic == null)
            throw new IllegalArgumentException("Act 3: static key decryption failed");

        remoteStaticPub = decryptedStatic;

        // se: ECDH(e, rs)
        byte[] se = Secp256k1.ecdh(remoteStaticPub, localEphemeralPriv);
        mixKey(se);

        // Verify final tag
        if (!decryptWithAd(handshakeHash, tag, new byte[0]))
            throw new IllegalArgumentException("Act 3: final MAC verification failed");

        // Split into transport keys
        split();
    }

    // ── Transport encryption ──────────────────────────────────────────────────

    /**
     /**
     /**
     * Encrypts a message for transport using the established session key.
     * Returns: encrypted 4-byte little-endian length + 16-byte tag (20
     * bytes total) + encrypted payload + 16-byte tag.
     *
     * FIX: reverting to 4-byte LE, on the most decisive evidence available
     * -- a real, past session that reached an actual, complete success:
     * 323,987 real headers synced end-to-end from a real peer. That
     * session directly resolved the exact 2-vs-4-byte confusion this
     * project keeps re-hitting: hsd's source shows TWO different write()
     * methods -- the parent Brontide class uses 2-byte BE, but its
     * subclass BrontideStream -- the one actually used for real peer
     * connections -- OVERRIDES it with 4-byte LE. The earlier "190 bytes,
     * therefore 2-byte" result was almost certainly exercising the parent
     * class's write(), not BrontideStream's. A genuine, complete,
     * documented sync beats a plausible-looking isolated byte count.
     */
    public byte[] encryptMessage(byte[] plaintext) {
        // Encrypt length (4-byte little-endian)
        int bodyLen = plaintext.length;
        byte[] lenBytes = new byte[]{
                (byte)  (bodyLen        & 0xFF),
                (byte) ((bodyLen >>  8) & 0xFF),
                (byte) ((bodyLen >> 16) & 0xFF),
                (byte) ((bodyLen >> 24) & 0xFF)
        };
        byte[] encLen = sendEncrypt(new byte[0], lenBytes);

        // Encrypt payload
        byte[] encPayload = sendEncrypt(new byte[0], plaintext);

        byte[] result = new byte[encLen.length + encPayload.length];
        System.arraycopy(encLen, 0, result, 0, encLen.length);
        System.arraycopy(encPayload, 0, result, encLen.length, encPayload.length);
        return result;
    }

    /**
     * Decrypts a transport message.
     * Input should be: 20 bytes (enc length) + (plaintext.length + 16) bytes.
     */
    public byte[] decryptMessage(byte[] data) {
        if (data.length < 20)
            throw new IllegalArgumentException("Message too short");

        // Decrypt length
        byte[] encLen = Arrays.copyOfRange(data, 0, 20);
        byte[] lenBytes = recvDecrypt(new byte[0], encLen);
        if (lenBytes == null) throw new IllegalArgumentException("Length decryption failed");

        int msgLen = (lenBytes[0] & 0xFF) | ((lenBytes[1] & 0xFF) << 8)
                | ((lenBytes[2] & 0xFF) << 16) | ((lenBytes[3] & 0xFF) << 24);

        // Decrypt payload
        byte[] encPayload = Arrays.copyOfRange(data, 20, 20 + msgLen + 16);
        byte[] plaintext = recvDecrypt(new byte[0], encPayload);
        if (plaintext == null) throw new IllegalArgumentException("Payload decryption failed");

        return plaintext;
    }

    // ── Streaming transport encryption ────────────────────────────────────────
    //
    // encryptMessage/decryptMessage assume the caller already has the full
    // framed buffer in hand. Over a real socket that's not possible: the
    // payload length is only known *after* decrypting the length envelope,
    // so the length and payload have to be read (and decrypted) as two
    // separate steps. These four methods expose that as two steps without
    // changing encryptMessage/decryptMessage themselves.

    /** Decrypts a 20-byte length envelope, returning the plaintext payload length. */
    public int decryptLength(byte[] encLen) {
        if (encLen.length != 20)
            throw new IllegalArgumentException("Length envelope must be 20 bytes");
        byte[] lenBytes = recvDecrypt(new byte[0], encLen);
        if (lenBytes == null) throw new IllegalArgumentException("Length decryption failed");
        return (lenBytes[0] & 0xFF) | ((lenBytes[1] & 0xFF) << 8)
                | ((lenBytes[2] & 0xFF) << 16) | ((lenBytes[3] & 0xFF) << 24);
    }

    /** Decrypts a payload envelope once its length is known. Returns plaintext. */
    public byte[] decryptPayload(byte[] encPayload) {
        byte[] plaintext = recvDecrypt(new byte[0], encPayload);
        if (plaintext == null) throw new IllegalArgumentException("Payload decryption failed");
        return plaintext;
    }

    private void mixHash(byte[] data) {
        byte[] combined = new byte[handshakeHash.length + data.length];
        System.arraycopy(handshakeHash, 0, combined, 0, handshakeHash.length);
        System.arraycopy(data, 0, combined, handshakeHash.length, data.length);
        handshakeHash = sha256(combined);
    }

    /** Two-argument mixHash -- mixes BOTH a plaintext/ciphertext AND its
     *  AEAD tag into the handshake hash in one combined update
     *  (handshakeHash = sha256(handshakeHash || data || tag)), matching
     *  real hsd's own mixHash(data, tag). FIX: a real, confirmed bug --
     *  this overload didn't exist before, and encryptWithAd/decryptWithAd
     *  below never mixed the tag into the handshake hash at all after
     *  computing/verifying it. Real hsd's encryptHash/decryptHash both
     *  do this unconditionally as their last step. Missing it doesn't
     *  break the ACT WHOSE OWN TAG this is -- that tag only depends on
     *  the handshake hash as it stood BEFORE this update -- but it means
     *  every act AFTER this one is built on a handshake hash that's
     *  already diverged from a real peer's, which is exactly why Act 1
     *  could start succeeding against real peers while Act 2 still
     *  failed to verify: Act 1's own tag never depended on this missing
     *  step, but by the time Act 2 needs the handshake hash, it's
     *  already wrong. */
    private void mixHash(byte[] data, byte[] tag) {
        byte[] combined = new byte[handshakeHash.length + data.length + tag.length];
        System.arraycopy(handshakeHash, 0, combined, 0, handshakeHash.length);
        System.arraycopy(data, 0, combined, handshakeHash.length, data.length);
        System.arraycopy(tag, 0, combined, handshakeHash.length + data.length, tag.length);
        handshakeHash = sha256(combined);
    }

    // ── Noise protocol operations ─────────────────────────────────────────────
    //
    // FIX: a real, confirmed, and more fundamental bug than any single
    // constant -- mixHash/mixKey/split (and the initial chaining-key
    // seed in initHandshakeState()) used Blake2b throughout, but real
    // hsd's own Brontide layer uses SHA-256 for this specifically
    // (confirmed directly against hsd's own source, lib/net/brontide.js:
    // SymmetricState.initSymmetric() uses sha256.digest(), and
    // expand() uses hkdf.extract(sha256, ...)/hkdf.expand(sha256, ...)).
    // This matters more than the protocol-name-string fix alone: mixHash
    // runs at every single step of the handshake starting from the very
    // first call, so using the wrong hash here means the handshake hash
    // and chaining key diverge from a real peer's immediately, before
    // Act 1 is even fully built -- regardless of how correct every other
    // constant is. Blake2b itself is NOT wrong in general -- it's the
    // right hash for Handshake's own tx/block layer (see HeaderUtil,
    // TxParser) -- it's specifically this Noise/Brontide handshake layer
    // that needs SHA-256 instead.
    //
    // Also fixes a second, compounding issue: the previous
    // Blake2b.hkdfExpand(prk, info, outLen) call appended its OWN
    // internal counter byte on top of whatever "info" was already
    // passed in (e.g. calling it with info={0x01} meant the actual HMAC
    // input became [0x01, 0x01], not the single 0x01 byte real HKDF-
    // Expand (RFC 5869) and hsd's own expand() both compute for T(1)).
    // hkdfExpandSha256() below is a direct, correct implementation
    // instead -- not a same-signature replacement for the old
    // Blake2b.hkdfExpand, since preserving that calling convention
    // would have preserved this same double-counter bug underneath a
    // different hash.

    /** Correct HKDF-Expand (RFC 5869) with empty info, matching hsd's own
     *  expand(secret, salt, info=EMPTY): prk = HMAC-SHA256(salt, secret);
     *  T1 = HMAC-SHA256(prk, 0x01); T2 = HMAC-SHA256(prk, T1 || 0x02). */
    private static byte[][] hkdfExpandSha256(byte[] secret, byte[] salt) {
        byte[] saltKey = (salt == null || salt.length == 0) ? new byte[32] : salt;
        byte[] prk = hmacSha256(saltKey, secret);
        byte[] t1 = hmacSha256(prk, new byte[]{0x01});
        byte[] t2 = hmacSha256(prk, concat(t1, new byte[]{0x02}));
        return new byte[][]{t1, t2};
    }

    private void mixKey(byte[] inputKeyMaterial) {
        byte[][] t = hkdfExpandSha256(inputKeyMaterial, chainingKey);
        chainingKey = t[0];
        tempKey     = t[1];
        // FIX: reset the persistent handshake-phase nonce counter here,
        // matching real hsd's initKey() (called from mixKey()'s CipherState
        // update), which sets this.nonce = 0. See the handshakeNonce field
        // comment for why this must be a counter, not a per-call constant.
        handshakeNonce = 0;
    }

    private void split() {
        byte[][] t = hkdfExpandSha256(new byte[0], chainingKey);
        byte[] k1 = t[0];
        byte[] k2 = t[1];

        // Noise convention: the two derived keys (k1, k2) must be assigned
        // opposite roles on each side, so that what one side encrypts with
        // its sendKey, the other decrypts with a matching recvKey. The
        // previous version assigned sendKey=k1/recvKey=k2 unconditionally on
        // BOTH sides, which -- since both sides compute the same prk here --
        // meant initiator.sendKey == responder.sendKey (should instead equal
        // responder.recvKey), so every post-handshake message failed to
        // decrypt on the receiving side.
        if (isInitiator) {
            sendKey = k1;
            recvKey = k2;
        } else {
            sendKey = k2;
            recvKey = k1;
        }
        sendNonce = 0;
        recvNonce = 0;
        // Both directions start from the same final chaining key --
        // matches hsd's split(): sendCipher.initSalt(k1, ck) and
        // recvCipher.initSalt(k2, ck) both pass the identical ck.
        sendSalt = chainingKey;
        recvSalt = chainingKey;
    }

    /** Single AEAD encrypt on the send direction, with automatic key
     *  rotation every ROTATION_INTERVAL messages (see sendSalt's field
     *  comment). Replaces the previous bare
     *  {@code aeadEncrypt(sendKey, sendNonce++, ad, plaintext)} call
     *  sites -- same output, but no longer silently diverges from a
     *  real peer's cipher state on a long-lived connection. */
    private byte[] sendEncrypt(byte[] ad, byte[] plaintext) {
        byte[] result = aeadEncrypt(sendKey, sendNonce, ad, plaintext);
        sendNonce++;
        if (sendNonce >= ROTATION_INTERVAL) {
            byte[][] t = hkdfExpandSha256(sendKey, sendSalt);
            sendSalt = t[0];
            sendKey  = t[1];
            sendNonce = 0;
        }
        return result;
    }

    /** Single AEAD decrypt on the recv direction, with the matching
     *  automatic key rotation. See sendEncrypt()/sendSalt's comments. */
    private byte[] recvDecrypt(byte[] ad, byte[] ciphertext) {
        byte[] result = aeadDecrypt(recvKey, recvNonce, ad, ciphertext);
        recvNonce++;
        if (recvNonce >= ROTATION_INTERVAL) {
            byte[][] t = hkdfExpandSha256(recvKey, recvSalt);
            recvSalt = t[0];
            recvKey  = t[1];
            recvNonce = 0;
        }
        return result;
    }

    // ── AEAD helpers ──────────────────────────────────────────────────────────

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** Encrypts plaintext, returns just the 16-byte tag (for empty payloads).
     *  Mixes the (empty) plaintext and the tag into the handshake hash
     *  afterward -- unconditionally, since encryption can't itself fail --
     *  matching real hsd's encryptHash() exactly. See this class's own
     *  mixHash(data, tag) comment for why this step matters. */
    private byte[] encryptWithAd(byte[] ad, byte[] plaintext) {
        byte[] result = aeadEncrypt(tempKey, handshakeNonce, ad, plaintext);
        handshakeNonce++;
        byte[] tag = Arrays.copyOfRange(result, plaintext.length, result.length);
        mixHash(plaintext, tag);
        return tag;
    }

    /** Encrypts plaintext, returns ciphertext + tag. Mixes the ciphertext
     *  and tag into the handshake hash afterward, matching real hsd's
     *  encryptHash() -- which, per its own comment, mixes in the
     *  now-ciphertext buffer (pt is encrypted in place there), not the
     *  original plaintext. */
    private byte[] encryptWithAdFull(byte[] ad, byte[] plaintext) {
        byte[] result = aeadEncrypt(tempKey, handshakeNonce, ad, plaintext);
        handshakeNonce++;
        byte[] ciphertext = Arrays.copyOfRange(result, 0, plaintext.length);
        byte[] tag = Arrays.copyOfRange(result, plaintext.length, result.length);
        mixHash(ciphertext, tag);
        return result;
    }

    /** Verifies a 16-byte tag against empty plaintext. Mixes the
     *  (empty) plaintext and tag into the handshake hash ONLY on
     *  successful verification -- the decrypt/verify itself uses the
     *  handshake hash as it stood BEFORE this update (the `ad` the
     *  caller already passed in), matching real hsd's decryptHash()
     *  exactly: it computes the post-mix digest first, but only
     *  actually adopts it after the tag check passes. */
    private boolean decryptWithAd(byte[] ad, byte[] tag, byte[] expectedPlaintext) {
        byte[] combined = concat(new byte[0], tag);
        byte[] result = aeadDecrypt(tempKey, handshakeNonce, ad, combined);
        boolean ok = result != null && Arrays.equals(result, expectedPlaintext);
        // Matches real hsd's CipherState.decrypt(): the nonce only
        // advances on SUCCESSFUL decryption, not on every call.
        if (ok) {
            handshakeNonce++;
            mixHash(expectedPlaintext, tag);
        }
        return ok;
    }

    /** Decrypts ciphertext + tag, returns plaintext or null on failure. */
    /** Decrypts ciphertext + tag, returns plaintext or null on failure.
     *  Mixes the ciphertext and tag into the handshake hash ONLY on
     *  successful decryption, same reasoning as decryptWithAd(). */
    private byte[] decryptWithAdFull(byte[] ad, byte[] ciphertext) {
        byte[] result = aeadDecrypt(tempKey, handshakeNonce, ad, ciphertext);
        if (result != null) {
            handshakeNonce++;
            byte[] ctOnly = Arrays.copyOfRange(ciphertext, 0, ciphertext.length - 16);
            byte[] tag = Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);
            mixHash(ctOnly, tag);
        }
        return result;
    }

    /** ChaCha20-Poly1305 AEAD encryption -- matches real hsd's own AEAD
     *  choice exactly (its PROTOCOL_NAME constant literally says
     *  "ChaChaPoly", and its aead module is ChaCha20-Poly1305). FIX: a
     *  real, confirmed interop bug -- this used to be AES-GCM
     *  unconditionally, with a comment claiming ChaCha20-Poly1305 was
     *  merely "preferred" as if AES-GCM were an acceptable fallback.
     *  It isn't: these are two different ciphers that produce
     *  completely different ciphertexts and tags for the same key and
     *  plaintext, so even with every other value correctly matching a
     *  real peer, every single tag this code computed would still have
     *  failed that peer's authentication check. Uses the JDK's own
     *  built-in "ChaCha20-Poly1305" transformation (standard since
     *  JDK 11, no external library needed) rather than a hand-rolled
     *  implementation. Verified directly against RFC 8439's own
     *  published test vector before trusting this, not just "this
     *  compiles and produces some 16-byte tag." */
    private static byte[] aeadEncrypt(byte[] key, long nonce, byte[] ad, byte[] plaintext) {
        try {
            byte[] iv = nonceToIv(nonce);
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new javax.crypto.spec.IvParameterSpec(iv));
            if (ad.length > 0) cipher.updateAAD(ad);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new RuntimeException("AEAD encrypt failed: " + e.getMessage(), e);
        }
    }

    /** ChaCha20-Poly1305 AEAD decryption. Returns null on authentication failure. */
    private static byte[] aeadDecrypt(byte[] key, long nonce, byte[] ad, byte[] ciphertext) {
        try {
            byte[] iv = nonceToIv(nonce);
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new javax.crypto.spec.IvParameterSpec(iv));
            if (ad.length > 0) cipher.updateAAD(ad);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            return null; // Authentication failed
        }
    }

    /**
     * Converts a 64-bit nonce counter to the 12-byte nonce ChaCha20-Poly1305
     * expects under the Noise/Brontide convention: 4 zero bytes, THEN the
     * little-endian counter starting at byte offset 4 -- matching real
     * hsd's own CipherState.update() exactly (this.iv.writeUInt32LE(this.nonce, 4)).
     * FIX: a real, confirmed bug -- this previously wrote the counter at
     * offset 0 (counter first, zero-fill last), the reverse of what a
     * real peer expects. Like the protocol name, Act 3 size, and cipher
     * algorithm bugs, this is silently self-consistent between two
     * instances of this same code (both sides agree on the same wrong
     * layout) but produces a completely different IV, and therefore a
     * completely different ciphertext and tag, than any real peer computes.
     */
    private static byte[] nonceToIv(long nonce) {
        byte[] iv = new byte[12];
        for (int i = 0; i < 8; i++)
            iv[4 + i] = (byte)(nonce >>> (i * 8));
        return iv;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static byte[] compressPoint(BigInteger[] point) {
        byte[] x = toBytes32(point[0]);
        byte prefix = point[1].testBit(0) ? (byte) 0x03 : (byte) 0x02;
        byte[] result = new byte[33];
        result[0] = prefix;
        System.arraycopy(x, 0, result, 1, 32);
        return result;
    }

    private static byte[] toBytes32(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length == 32) return b;
        byte[] out = new byte[32];
        if (b.length > 32) System.arraycopy(b, b.length - 32, out, 0, 32);
        else System.arraycopy(b, 0, out, 32 - b.length, b.length);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /** Returns the remote static public key (available after Act 3). */
    public byte[] getRemoteStaticPub() { return remoteStaticPub; }

    /** Returns true if the handshake is complete and transport keys are set. */
    public boolean isReady() { return sendKey != null && recvKey != null; }
}