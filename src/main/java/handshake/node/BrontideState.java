package handshake.node;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
 * <p>
 * Protocol: Noise_XK with:
 *   - Curve:    secp256k1
 *   - Hash:     SHA-256 (Noise/Brontide layer; Blake2b is used elsewhere
 *               in Handshake for tx/block hashing, not here)
 *   - Cipher:   ChaCha20-Poly1305 (real, as of this fix -- was AES-GCM before)
 *   - Encoding: Elligator2 for public key representation
 * <p>
 * Handshake sequence (initiator → responder):
 *   Act 1 (80 bytes):  initiator sends ephemeral key + encrypted payload
 *   Act 2 (80 bytes):  responder sends ephemeral key + encrypted payload
 *   Act 3 (66 bytes):  initiator sends static key + encrypted payload
 * <p>
 * After Act 3 both sides have shared session keys for encrypted transport.
 * <p>
 * Reference: hsd/lib/net/brontide.js
 */
public class BrontideState {

    // ── Constants ─────────────────────────────────────────────────────────────

    public static final int ACT_ONE_SIZE   = 80;  // elligator(64) + tag(16)
    public static final int ACT_TWO_SIZE   = 80;
    public static final int ACT_THREE_SIZE = 65;  // encrypted static key(33) + tag1(16) + tag2(16)

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

    // Remote ephemeral (received during handshake)
    private BigInteger[] remoteEphemeralPubPoint;

    // Noise state
    private byte[] chainingKey;   // ck
    private byte[] handshakeHash; // h
    private byte[] tempKey;       // temp_k

    /**
     * Real, persistent handshake-phase nonce counter -- NOT hardcoded to 0.
     * Confirmed against real hsd source (lib/net/brontide.js CipherState):
     * nonce increments after EVERY encrypt/decrypt call (both directions
     * share one counter during the handshake), and resets to 0 only when
     * mixKey() is called. Previously this was hardcoded to 0 for every
     * handshake-phase operation, which happened to be correct for Act 1
     * and Act 2 (a mixKey call always immediately precedes those) but is
     * WRONG for Act 3's first operation (encrypting the static key) --
     * Act 2's tag verification (a decrypt) already increments this to 1,
     * and no mixKey happens before Act 3's static-key encryption. This is
     * confirmed to be the exact cause of real hsd's "Act three: bad tag".
     */
    private long handshakeNonce = 0;

    // Transport keys (set after Act 3)
    private byte[] sendKey;
    private byte[] recvKey;
    private long   sendNonce;
    private long   recvNonce;
    /**
     * Key-rotation salts, one per direction. Real hsd rotates both
     * transport keys every ROTATION_INTERVAL (1000) messages -- confirmed
     * directly against lib/net/brontide.js's CipherState.rotateKey().
     * Without this, a connection that exchanges 1000+ messages in either
     * direction (which real, sustained header/block sync easily does)
     * starts failing to decrypt from that exact point on, since the real
     * peer has moved on to a new key we never derived. Both salts start
     * as the same value: the final Noise chaining key at the moment
     * split() runs (confirmed: both sendCipher.initSalt() and
     * recvCipher.initSalt() are called with the same `this.chain`).
     */
    private byte[] sendSalt;
    private byte[] recvSalt;
    private static final long ROTATION_INTERVAL = 1000;

    private static final SecureRandom RNG = new SecureRandom();

    // ── Constructor ───────────────────────────────────────────────────────────

    /**
     * Creates a Brontide state for initiating a connection.
     * <p>
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
     * <p>
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
        // Initialize chaining key and hash with protocol name.
        // "Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared" is the real
        // protocol name string, confirmed against the actual hsd source
        // (previously this was a fabricated string naming BLAKE2b, which
        // is wrong -- see mixHash/mixKey below for why that mattered).
        String protocolName = "Noise_XK_secp256k1_ChaChaPoly_SHA256+SVDW_Squared";
        byte[] nameBytes = protocolName.getBytes(StandardCharsets.UTF_8);
        if (nameBytes.length <= 32) {
            chainingKey = new byte[32];
            System.arraycopy(nameBytes, 0, chainingKey, 0, nameBytes.length);
        } else {
            chainingKey = sha256(nameBytes);
        }
        handshakeHash = chainingKey.clone();

        // Mix in prologue
        mixHash(PROLOGUE.getBytes(StandardCharsets.UTF_8));

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
        do {
            localEphemeralPriv = new byte[32];
            RNG.nextBytes(localEphemeralPriv);
            localEphemeralPubPoint = Secp256k1.pubKeyPoint(localEphemeralPriv);
        } while (Elligator.encode(localEphemeralPubPoint) == null);
        // Keep trying until we get an Elligator-encodable key
    }

    // ── Act 1 (Initiator → Responder) ─────────────────────────────────────────

    /**
     * Generates Act 1 message (80 bytes) as the initiator.
     * Sends: Elligator(ephemeral_pub) + AEAD(empty, h)
     */
    public byte[] genActOne() {
        byte[] ephemeralEncoded = Elligator.encode(localEphemeralPubPoint);
        if (ephemeralEncoded == null)
            throw new IllegalStateException("Ephemeral key not Elligator-encodable");

        // e
        mixHash(Secp256k1.compressedPublicKey(localEphemeralPriv));

        // es: ECDH(e, rs)
        byte[] es = Secp256k1.ecdh(remoteStaticPub, localEphemeralPriv);
        mixKey(es);

        // Encrypt empty payload
        byte[] tag = encryptWithAd(new byte[0]);

        byte[] act = new byte[ACT_ONE_SIZE];
        System.arraycopy(ephemeralEncoded, 0, act, 0, 64);
        System.arraycopy(tag, 0, act, 64, 16);
        return act;
    }

    /**
     * Processes Act 1 as the responder.
     * Reads: Elligator(ephemeral_pub) + AEAD tag
     * <p>
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
        if (!decryptWithAd(tag, new byte[0]))
            throw new IllegalArgumentException("Act 1: MAC verification failed");
    }

    // ── Act 2 (Responder → Initiator) ─────────────────────────────────────────

    /**
     * Generates Act 2 message (80 bytes) as the responder.
     */
    public byte[] genActTwo() {
        byte[] ephemeralEncoded = Elligator.encode(localEphemeralPubPoint);
        if (ephemeralEncoded == null)
            throw new IllegalStateException("Ephemeral key not Elligator-encodable");

        byte[] localEphPub = Secp256k1.compressedPublicKey(localEphemeralPriv);

        // e
        mixHash(localEphPub);

        // ee: ECDH(e, re)
        byte[] remoteEphPub = compressPoint(remoteEphemeralPubPoint);
        byte[] ee = Secp256k1.ecdh(remoteEphPub, localEphemeralPriv);
        mixKey(ee);

        // Encrypt empty payload
        byte[] tag = encryptWithAd(new byte[0]);

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
        if (!decryptWithAd(tag, new byte[0]))
            throw new IllegalArgumentException("Act 2: MAC verification failed");
    }

    // ── Act 3 (Initiator → Responder) ─────────────────────────────────────────

    /**
     * Generates Act 3 message (66 bytes) as the initiator.
     * Sends encrypted static key + final AEAD payload.
     */
    public byte[] genActThree() {
        // Encrypt our static public key
        byte[] encryptedStatic = encryptWithAdFull(localStaticPub);

        // se: ECDH(s, re)
        byte[] remoteEphPub = compressPoint(remoteEphemeralPubPoint);
        byte[] se = Secp256k1.ecdh(remoteEphPub, localStaticPriv);
        mixKey(se);

        // Encrypt empty payload (final tag)
        byte[] tag = encryptWithAd(new byte[0]);

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
        byte[] decryptedStatic = decryptWithAdFull(encryptedStatic);
        if (decryptedStatic == null)
            throw new IllegalArgumentException("Act 3: static key decryption failed");

        remoteStaticPub = decryptedStatic;

        // se: ECDH(e, rs)
        byte[] se = Secp256k1.ecdh(remoteStaticPub, localEphemeralPriv);
        mixKey(se);

        // Verify final tag
        if (!decryptWithAd(tag, new byte[0]))
            throw new IllegalArgumentException("Act 3: final MAC verification failed");

        // Split into transport keys
        split();
    }

    // ── Transport encryption ──────────────────────────────────────────────────

    /**
     * Encrypts a message for transport using the established session key.
     * Returns: encrypted 4-byte LITTLE-ENDIAN length + 16-byte tag + encrypted payload + 16-byte tag.
     * <p>
     * The wire format here went back and forth (2-byte BE vs 4-byte LE) --
     * hsd's source has TWO different write() methods (Brontide's parent-class
     * version uses 2-byte BE; BrontideStream's, which OVERRIDES it and is
     * what real peer connections actually use, uses 4-byte LE:
     * len.writeUInt32LE(data.length, 0)). A live connection test confirmed
     * this directly: switching to 4-byte LE was the first time a real peer
     * ever sent back actual response bytes (20 bytes) instead of silently
     * closing the connection.
     */
    public byte[] encryptMessage(byte[] plaintext) {
        byte[] encLen = encryptLength(plaintext.length);
        byte[] encPayload = aeadEncrypt(sendKey, sendNonce, new byte[0], plaintext);
        sendNonce++;
        if (sendNonce == ROTATION_INTERVAL) rotateSendKey();

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

        byte[] encLen = Arrays.copyOfRange(data, 0, 20);
        int msgLen = decryptLength(encLen);

        byte[] encPayload = Arrays.copyOfRange(data, 20, 20 + msgLen + 16);
        byte[] plaintext = aeadDecrypt(recvKey, recvNonce, new byte[0], encPayload);
        if (plaintext == null) throw new IllegalArgumentException("Payload decryption failed");
        recvNonce++;
        if (recvNonce == ROTATION_INTERVAL) rotateRecvKey();

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

    /** Encrypts just the 4-byte little-endian length prefix. Returns 20 bytes (ciphertext + tag). */
    public byte[] encryptLength(int len) {
        byte[] lenBytes = new byte[]{
                (byte) len, (byte) (len >>> 8), (byte) (len >>> 16), (byte) (len >>> 24)
        };
        byte[] result = aeadEncrypt(sendKey, sendNonce, new byte[0], lenBytes);
        sendNonce++;
        if (sendNonce == ROTATION_INTERVAL) rotateSendKey();
        return result;
    }

    /** Encrypts the payload. Returns plaintext.length + 16 bytes (ciphertext + tag). */
    public byte[] encryptPayload(byte[] plaintext) {
        byte[] result = aeadEncrypt(sendKey, sendNonce, new byte[0], plaintext);
        sendNonce++;
        if (sendNonce == ROTATION_INTERVAL) rotateSendKey();
        return result;
    }

    /** Decrypts a 20-byte length envelope, returning the plaintext payload length. */
    public int decryptLength(byte[] encLen) {
        if (encLen.length != 20)
            throw new IllegalArgumentException("Length envelope must be 20 bytes");
        byte[] lenBytes = aeadDecrypt(recvKey, recvNonce, new byte[0], encLen);
        if (lenBytes == null) throw new IllegalArgumentException("Length decryption failed");
        recvNonce++;
        if (recvNonce == ROTATION_INTERVAL) rotateRecvKey();
        return (lenBytes[0] & 0xFF) | ((lenBytes[1] & 0xFF) << 8)
                | ((lenBytes[2] & 0xFF) << 16) | ((lenBytes[3] & 0xFF) << 24);
    }

    /** Decrypts a payload envelope once its length is known. Returns plaintext. */
    public byte[] decryptPayload(byte[] encPayload) {
        byte[] plaintext = aeadDecrypt(recvKey, recvNonce, new byte[0], encPayload);
        if (plaintext == null) throw new IllegalArgumentException("Payload decryption failed");
        recvNonce++;
        if (recvNonce == ROTATION_INTERVAL) rotateRecvKey();
        return plaintext;
    }

    // ── Noise protocol operations ─────────────────────────────────────────────
    //
    // mixHash/mixKey/split now use SHA-256 (plain digest for mixHash, HMAC-SHA256
    // for the HKDF in mixKey/split) instead of Blake2b, matching real hsd's
    // Brontide layer -- confirmed against a verified-working reference
    // (CryptoUtils.java from a prior session that achieved a real handshake
    // against a live node). Blake2b is still correct and used elsewhere in
    // Handshake (tx ids, block hashes) -- it's specifically the Noise/Brontide
    // handshake layer that uses SHA-256, not the blockchain layer.

    private void mixHash(byte[] data) {
        byte[] combined = new byte[handshakeHash.length + data.length];
        System.arraycopy(handshakeHash, 0, combined, 0, handshakeHash.length);
        System.arraycopy(data, 0, combined, handshakeHash.length, data.length);
        handshakeHash = sha256(combined);
    }

    /** Two-argument form: mixes BOTH data and tag into the hash in one step,
     *  matching Noise's EncryptAndHash/DecryptAndHash (which hash the full
     *  ciphertext-including-tag, not just the plaintext). Needed after every
     *  encrypt/decrypt call -- the single-arg mixHash above was, until now,
     *  never followed by a call that mixed the tag in at all for empty-payload
     *  operations (Act 1/2's tag, Act 3's final tag), silently self-consistent
     *  between two instances of our own code but wrong against a real peer. */
    private void mixHash(byte[] data, byte[] tag) {
        byte[] combined = new byte[handshakeHash.length + data.length + tag.length];
        System.arraycopy(handshakeHash, 0, combined, 0, handshakeHash.length);
        System.arraycopy(data, 0, combined, handshakeHash.length, data.length);
        System.arraycopy(tag, 0, combined, handshakeHash.length + data.length, tag.length);
        handshakeHash = sha256(combined);
    }

    /**
     * HKDF matching hsd's expand(secret, salt, info=EMPTY):
     *   prk = HMAC-SHA256(key=salt, data=secret)
     *   T1  = HMAC-SHA256(key=prk, data=0x01)
     *   T2  = HMAC-SHA256(key=prk, data=T1 || 0x02)
     *   returns [T1, T2]
     */
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
        handshakeNonce = 0; // matches real hsd: initKey(temp) resets nonce to 0
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
        // Both directions' initial salt is the same value: the final
        // Noise chaining key at this exact moment (confirmed against
        // real hsd source: both initSalt() calls in split() pass
        // `this.chain`, regardless of role).
        sendSalt = chainingKey.clone();
        recvSalt = chainingKey.clone();
        sendNonce = 0;
        recvNonce = 0;
    }

    /**
     * Real hsd's CipherState.rotateKey(): derives a new (salt, key) pair
     * from the current key using the SAME HKDF construction as
     * everywhere else (secret=old key, salt=current salt, info=empty),
     * then resets that direction's nonce to 0. Confirmed directly against
     * lib/net/brontide.js.
     */
    private void rotateSendKey() {
        byte[][] t = hkdfExpandSha256(sendKey, sendSalt);
        sendSalt = t[0];
        sendKey  = t[1];
        sendNonce = 0;
    }

    private void rotateRecvKey() {
        byte[][] t = hkdfExpandSha256(recvKey, recvSalt);
        recvSalt = t[0];
        recvKey  = t[1];
        recvNonce = 0;
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

    /** Encrypts an empty payload, returns just the 16-byte tag, and mixes
     *  (empty-ciphertext, tag) into handshakeHash afterward. */
    private byte[] encryptWithAd(byte[] plaintext) {
        byte[] result = aeadEncrypt(tempKey, handshakeNonce++, handshakeHash, plaintext);
        byte[] ciphertext = Arrays.copyOfRange(result, 0, plaintext.length);
        byte[] tag = Arrays.copyOfRange(result, plaintext.length, result.length);
        mixHash(ciphertext, tag);
        return tag;
    }

    /** Encrypts plaintext, returns ciphertext + tag, and mixes them into
     *  handshakeHash afterward (used for Act 3's 33-byte static key). */
    private byte[] encryptWithAdFull(byte[] plaintext) {
        byte[] result = aeadEncrypt(tempKey, handshakeNonce++, handshakeHash, plaintext);
        byte[] ciphertext = Arrays.copyOfRange(result, 0, plaintext.length);
        byte[] tag = Arrays.copyOfRange(result, plaintext.length, result.length);
        mixHash(ciphertext, tag);
        return result;
    }

    /** Verifies a 16-byte tag against an empty plaintext, mixing (empty, tag)
     *  into handshakeHash only if verification succeeds. */
    private boolean decryptWithAd(byte[] tag, byte[] expectedPlaintext) {
        byte[] newHash = shaConcat(handshakeHash, expectedPlaintext, tag);
        byte[] result = aeadDecrypt(tempKey, handshakeNonce++, handshakeHash, tag);
        boolean ok = result != null && Arrays.equals(result, expectedPlaintext);
        if (ok) handshakeHash = newHash;
        return ok;
    }

    /** Decrypts ciphertext + tag, returns plaintext or null on failure,
     *  mixing (ciphertext, tag) into handshakeHash only on success. */
    private byte[] decryptWithAdFull(byte[] ciphertextPlusTag) {
        int ctLen = ciphertextPlusTag.length - 16;
        byte[] ct = Arrays.copyOfRange(ciphertextPlusTag, 0, ctLen);
        byte[] tag = Arrays.copyOfRange(ciphertextPlusTag, ctLen, ciphertextPlusTag.length);
        byte[] newHash = shaConcat(handshakeHash, ct, tag);
        byte[] plaintext = aeadDecrypt(tempKey, handshakeNonce++, handshakeHash, ciphertextPlusTag);
        if (plaintext != null) handshakeHash = newHash;
        return plaintext;
    }

    private static byte[] shaConcat(byte[] a, byte[] b, byte[] c) {
        byte[] combined = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        System.arraycopy(c, 0, combined, a.length + b.length, c.length);
        return sha256(combined);
    }

    /**
     * Real ChaCha20-Poly1305 AEAD encryption, matching Brontide's actual
     * protocol (the class's own protocol name string always said
     * ChaChaPoly, but the implementation used AES-GCM until now -- two
     * instances of this code agree with each other regardless of which
     * cipher is used, which is exactly why this went undetected in our
     * own local handshake tests but fails against any real hsd peer).
     */
    private static byte[] aeadEncrypt(byte[] key, long nonce, byte[] ad, byte[] plaintext) {
        try {
            byte[] iv = nonceToIv(nonce);
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new IvParameterSpec(iv));
            if (ad.length > 0) cipher.updateAAD(ad);
            return cipher.doFinal(plaintext);
        } catch (Exception e) {
            throw new RuntimeException("AEAD encrypt failed: " + e.getMessage(), e);
        }
    }

    /** Real ChaCha20-Poly1305 AEAD decryption. Returns null on authentication failure. */
    private static byte[] aeadDecrypt(byte[] key, long nonce, byte[] ad, byte[] ciphertext) {
        try {
            byte[] iv = nonceToIv(nonce);
            Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "ChaCha20"),
                    new IvParameterSpec(iv));
            if (ad.length > 0) cipher.updateAAD(ad);
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            return null; // Authentication failed
        }
    }

    /**
     * Converts a 64-bit nonce counter to the 12-byte nonce ChaCha20-Poly1305
     * expects under the Noise protocol convention: 4 zero bytes, THEN the
     * 8-byte little-endian counter (zero-prefix first, counter last). The
     * previous version had this backwards -- counter first, zero-fill last
     * -- which (like the AES/ChaCha mismatch above) is silently
     * self-consistent between two instances of our own code but wrong
     * against any real peer.
     */
    /**
     * Converts a nonce counter to the 12-byte IV, per hsd's real convention:
     * a 4-byte little-endian uint32 at bytes 4-7 ONLY (bytes 0-3 and 8-11
     * stay zero) -- confirmed exactly against hsd's CipherState.update():
     * `this.iv.writeUInt32LE(this.nonce, 4)`, which writes just 4 bytes.
     * <p>
     * This was analyzed and reasoned through earlier but the actual code
     * change was never applied to this shared function -- it still wrote
     * an 8-byte counter across bytes 4-11. That's invisible during the
     * Act 1/2/3 handshake phase specifically, since the handshake nonce is
     * always 0 there (both encodings produce identical all-zero bytes for
     * nonce=0), which is exactly why the crypto handshake could be
     * independently verified correct against real ground truth while this
     * bug remained hidden. It only bites the moment a nonce actually
     * increments past 0 -- which is the very first thing that happens once
     * transport-phase messages (starting with VERSION) begin sending.
     */
    private static byte[] nonceToIv(long nonce) {
        byte[] iv = new byte[12];
        iv[4] = (byte) (nonce);
        iv[5] = (byte) (nonce >>> 8);
        iv[6] = (byte) (nonce >>> 16);
        iv[7] = (byte) (nonce >>> 24);
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

    /** DEBUG ONLY: exposes the ephemeral private key for a specific
     *  connection attempt, so a real failure can be independently
     *  recomputed and cross-checked end to end with the exact same keys. */
    public byte[] debugLocalEphemeralPriv() { return localEphemeralPriv; }

    /** DEBUG ONLY: exposes the current receive-side nonce counter, to help
     *  diagnose transport-phase decrypt failures during real testing. */
    public long debugRecvNonce() { return recvNonce; }
}