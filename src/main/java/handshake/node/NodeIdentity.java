package handshake.node;

import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;

/**
 * NodeIdentity — manages the node's persistent Brontide keypair.
    * <p>
 * The node key is a 32-byte secp256k1 private key stored in `node.key`
 * in the data directory. It is generated once and reused across restarts.
    * <p>
 * The corresponding compressed public key is the node's identity on the
 * Handshake P2P network — peers use it to establish encrypted Brontide
 * connections.
    * <p>
 * The Brontide address format is:
 *   base32(compressedPubKey)@ip:port
 */
public class NodeIdentity {

    // ── Singleton ─────────────────────────────────────────────────────────────

    private static volatile NodeIdentity instance;

    public static NodeIdentity load(String dataDir) {
        if (instance == null) {
            synchronized (NodeIdentity.class) {
                if (instance == null) instance = new NodeIdentity(dataDir);
            }
        }
        return instance;
    }

    public static NodeIdentity get() {
        if (instance == null) throw new IllegalStateException("NodeIdentity not loaded");
        return instance;
    }

    // ── Fields ────────────────────────────────────────────────────────────────

    private final byte[] privateKey;   // 32 bytes
    private final byte[] publicKey;    // 33 bytes compressed

    // ── Constructor ───────────────────────────────────────────────────────────

    private NodeIdentity(String dataDir) {
        Path keyPath = Path.of(dataDir, "node.key");
        byte[] privKey;

        if (Files.exists(keyPath)) {
            try {
                String hex = Files.readString(keyPath).strip();
                privKey = fromHex(hex);
                System.out.println("[Identity] Loaded node key from " + keyPath);
            } catch (IOException e) {
                throw new RuntimeException("Failed to read node.key: " + e.getMessage(), e);
            }
        } else {
            // Generate new key
            privKey = new byte[32];
            new SecureRandom().nextBytes(privKey);
            try {
                Files.createDirectories(keyPath.getParent());
                Files.writeString(keyPath, hex(privKey));
                System.out.println("[Identity] Generated new node key at " + keyPath);
            } catch (IOException e) {
                throw new RuntimeException("Failed to write node.key: " + e.getMessage(), e);
            }
        }

        this.privateKey = privKey;
        this.publicKey  = Secp256k1.compressedPublicKey(privKey);

        System.out.println("[Identity] Node public key: " + hex(publicKey));
        System.out.println("[Identity] Brontide address: "
                + base32Encode(publicKey) + "@<yourIP>:44806");
    }

    // ── Public API ────────────────────────────────────────────────────────────

    public byte[] getPrivateKey()  { return privateKey.clone(); }
    public byte[] getPublicKey()   { return publicKey.clone(); }

    public String getPublicKeyHex() { return hex(publicKey); }

    public String getBrontideAddress(String ip, int port) {
        return base32Encode(publicKey) + "@" + ip + ":" + port;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] fromHex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return b;
    }

    /**
     * Base32 encoding (RFC 4648, lowercase, no padding).
     * Used for Brontide address key encoding.
     */
    public static String base32Encode(byte[] data) {
        final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
        StringBuilder sb = new StringBuilder();
        int buffer = 0, bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                sb.append(ALPHABET.charAt((buffer >> bitsLeft) & 0x1F));
            }
        }
        if (bitsLeft > 0) {
            sb.append(ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return sb.toString();
    }

    /**
     * Base32 decoding (RFC 4648, lowercase, no padding).
     */
    public static byte[] base32Decode(String s) {
        final String ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
        s = s.toLowerCase().replaceAll("[^a-z2-7]", "");
        byte[] out = new byte[s.length() * 5 / 8];
        int buffer = 0, bitsLeft = 0, idx = 0;
        for (char c : s.toCharArray()) {
            int val = ALPHABET.indexOf(c);
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                out[idx++] = (byte) (buffer >> bitsLeft);
            }
        }
        return idx == out.length ? out : java.util.Arrays.copyOf(out, idx);
    }
}