package handshake.node;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A name's Urkel tree key -- confirmed directly from real hsd's
 * rules.js: hashBinary() calls "sha3.digest(name)", NOT Blake2b. This
 * is a real, deliberate exception to this project's usual "Handshake
 * replaces SHA256 with Blake2b everywhere" pattern -- the tree's own
 * internal node hashing (see UrkelHash) genuinely is BLAKE2b-256
 * (confirmed via a live cross-check against real urkel/bcrypto
 * producing an identical root hash), but the name-to-key mapping used
 * to navigate into that tree is a completely separate, independent
 * choice, and it's SHA3-256, confirmed via bcrypto's own sha3.js
 * (SHA3.id = 'SHA3_256', SHA3.size = 32).
 *
 * Uses Java's own native SHA3-256 (available since Java 9), not a
 * hand-rolled implementation -- no reason to reimplement a NIST
 * FIPS 202 standard hash the JDK already provides and Java's own
 * MessageDigest infrastructure already tests.
 */
public final class UrkelNameHash {

    private UrkelNameHash() {}

    /** Matches rules.hashString(): the name string, written as plain
     *  ASCII bytes, then SHA3-256'd -- confirmed from rules.js's own
     *  "slab.write(name, 0, slab.length, 'ascii')" followed by
     *  hashBinary(buf). */
    public static byte[] hashName(String name) {
        try {
            MessageDigest sha3 = MessageDigest.getInstance("SHA3-256");
            return sha3.digest(name.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            // SHA3-256 has been a standard JDK algorithm since Java 9;
            // this project targets 21+, so this should be unreachable.
            throw new RuntimeException("SHA3-256 not available", e);
        }
    }
}