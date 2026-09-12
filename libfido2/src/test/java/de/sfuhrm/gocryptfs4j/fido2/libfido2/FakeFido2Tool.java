package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * A fake stand-in for the libfido2 {@code fido2-cred} and {@code fido2-assert}
 * tools, implementing the documented input/output contract.
 *
 * <p>It is a plain Java program with a {@code main} method, so a test can spawn
 * it as a real subprocess on any operating system without a FIDO2 device or
 * shell scripts. It reads the same standard input and writes the same standard
 * output as the real tools.</p>
 */
public final class FakeFido2Tool {

    /** The credential ID returned by the fake {@code fido2-cred -M}. */
    public static final byte[] CREDENTIAL_ID = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    };

    private FakeFido2Tool() {
    }

    /**
     * Runs the fake tool.
     *
     * @param args the tool arguments; {@code -M} means make-credential, anything
     *             else is treated as get-assertion
     * @throws Exception on I/O or digest errors
     */
    public static void main(String[] args) throws Exception {
        if (Arrays.asList(args).contains("-M")) {
            emit("client-data-hash", "gocryptfs", "es256", "authenticator-data",
                    base64(CREDENTIAL_ID), "attestation-signature");
            return;
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
            reader.readLine(); // client data hash
            reader.readLine(); // relying party id
            byte[] credentialId = Base64.getDecoder().decode(reader.readLine());
            byte[] hmacSalt = Base64.getDecoder().decode(reader.readLine());
            emit("client-data-hash", "gocryptfs", "authenticator-data", "assertion-signature",
                    base64(expectedSecret(credentialId, hmacSalt)));
        }
    }

    /**
     * Recomputes the HMAC secret the fake tool reports, so tests can assert the
     * exact credential ID and salt that crossed the process boundary.
     *
     * @param credentialId the credential ID
     * @param hmacSalt     the HMAC salt
     * @return the fake HMAC secret
     * @throws Exception if SHA-256 is unavailable
     */
    public static byte[] expectedSecret(byte[] credentialId, byte[] hmacSalt) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(credentialId);
        digest.update(hmacSalt);
        return digest.digest();
    }

    private static void emit(String... lines) {
        for (String line : lines) {
            System.out.println(line);
        }
    }

    private static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }
}
