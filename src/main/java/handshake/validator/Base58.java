package handshake.validator;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Base58 / Base58Check — standard Bitcoin-style alphabet, used by
 * Handshake's own WIF (Wallet Import Format) private-key encoding.
    * <p>
 * Confirmed directly against real hsd source (lib/primitives/keyring.js):
 * WIF's checksum uses "hash256" (standard double-SHA256), NOT Blake2b --
 * a genuine, real exception to Handshake's usual pattern of replacing
 * SHA256d with Blake2b everywhere, so this is deliberately NOT reusing
 * this project's Blake2b implementation here.
 */
public final class Base58 {

    private Base58() {}

    private static final String ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    public static String encode(byte[] input) {
        int leadingZeros = 0;
        while (leadingZeros < input.length && input[leadingZeros] == 0) leadingZeros++;

        BigInteger num = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while (num.signum() > 0) {
            BigInteger[] divRem = num.divideAndRemainder(BASE);
            sb.append(ALPHABET.charAt(divRem[1].intValue()));
            num = divRem[0];
        }
        for (int i = 0; i < leadingZeros; i++) sb.append('1');
        return sb.reverse().toString();
    }

    public static byte[] decode(String input) {
        int leadingOnes = 0;
        while (leadingOnes < input.length() && input.charAt(leadingOnes) == '1') leadingOnes++;

        BigInteger num = BigInteger.ZERO;
        for (int i = 0; i < input.length(); i++) {
            int digit = ALPHABET.indexOf(input.charAt(i));
            if (digit < 0) throw new IllegalArgumentException("Invalid base58 character: " + input.charAt(i));
            num = num.multiply(BASE).add(BigInteger.valueOf(digit));
        }

        byte[] numBytes = num.toByteArray();
        // BigInteger.toByteArray() can include a leading zero sign byte,
        // or produce fewer bytes than expected -- strip/pad accordingly.
        int start = (numBytes.length > 1 && numBytes[0] == 0) ? 1 : 0;
        byte[] body = Arrays.copyOfRange(numBytes, start, numBytes.length);

        byte[] result = new byte[leadingOnes + body.length];
        System.arraycopy(body, 0, result, leadingOnes, body.length);
        return result;
    }

    /** Standard double-SHA256, matching real hsd's "hash256" -- distinct
     *  from this project's Blake2b, deliberately, per the class comment. */
    private static byte[] hash256(byte[] data) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(sha256.digest(data));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String encodeCheck(byte[] payload) {
        byte[] checksum = Arrays.copyOf(hash256(payload), 4);
        byte[] full = new byte[payload.length + 4];
        System.arraycopy(payload, 0, full, 0, payload.length);
        System.arraycopy(checksum, 0, full, payload.length, 4);
        return encode(full);
    }

    /** Returns the payload (with checksum verified and stripped), or
     *  throws if the checksum doesn't match. */
    public static byte[] decodeCheck(String input) {
        byte[] full = decode(input);
        if (full.length < 4) throw new IllegalArgumentException("Base58Check data too short");
        byte[] payload = Arrays.copyOf(full, full.length - 4);
        byte[] checksum = Arrays.copyOfRange(full, full.length - 4, full.length);
        byte[] expected = Arrays.copyOf(hash256(payload), 4);
        if (!Arrays.equals(checksum, expected))
            throw new IllegalArgumentException("Base58Check checksum mismatch");
        return payload;
    }
}