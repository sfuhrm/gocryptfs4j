package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LibFido2TokenTest {

    private static final String DEVICE = "/dev/hidraw5";
    private static final byte[] CREDENTIAL_ID = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
    };
    private static final byte[] HMAC_SALT = new byte[32];

    @Test
    void registerCredentialBuildsCommandAndParsesOutput() throws IOException {
        RecordingRunner runner = new RecordingRunner(Arrays.asList(
                "cdh", Fido2Token.RELYING_PARTY_ID, "es256", "auth-data", base64(CREDENTIAL_ID), "sig"));
        LibFido2Token token = new LibFido2Token(DEVICE, "fido2-cred", "fido2-assert", runner);

        byte[] credentialId = token.registerCredential("alice");

        assertArrayEquals(CREDENTIAL_ID, credentialId);
        assertEquals(Arrays.asList("fido2-cred", "-M", "-h", DEVICE), runner.lastCommand);
        assertEquals(4, runner.lastStdin.size());
        assertEquals(Fido2Token.RELYING_PARTY_ID, runner.lastStdin.get(1));
        assertEquals("alice", runner.lastStdin.get(2));
        assertEquals(32, Base64.getDecoder().decode(runner.lastStdin.get(0)).length);
        assertEquals(32, Base64.getDecoder().decode(runner.lastStdin.get(3)).length);
    }

    @Test
    void hmacSecretBuildsCommandWithOptionsAndParsesOutput() throws IOException {
        byte[] secret = new byte[32];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) (i + 1);
        }
        RecordingRunner runner = new RecordingRunner(Arrays.asList(
                "cdh", Fido2Token.RELYING_PARTY_ID, "auth-data", "sig", base64(secret)));
        LibFido2Token token = new LibFido2Token(DEVICE, "fido2-cred", "fido2-assert", runner);

        byte[] result = token.hmacSecret(CREDENTIAL_ID, HMAC_SALT, Arrays.asList("uv=false", "pin=true"));

        assertArrayEquals(secret, result);
        assertEquals(Arrays.asList("fido2-assert", "-G", "-h",
                "-t", "uv=false", "-t", "pin=true", DEVICE), runner.lastCommand);
        assertEquals(4, runner.lastStdin.size());
        assertEquals(Fido2Token.RELYING_PARTY_ID, runner.lastStdin.get(1));
        assertEquals(base64(CREDENTIAL_ID), runner.lastStdin.get(2));
        assertEquals(base64(HMAC_SALT), runner.lastStdin.get(3));
    }

    @Test
    void hmacSecretWithoutOptions() throws IOException {
        RecordingRunner runner = new RecordingRunner(Arrays.asList(
                "cdh", Fido2Token.RELYING_PARTY_ID, "auth-data", "sig", base64(CREDENTIAL_ID)));
        LibFido2Token token = new LibFido2Token(DEVICE, "fido2-cred", "fido2-assert", runner);

        token.hmacSecret(CREDENTIAL_ID, HMAC_SALT, Collections.<String>emptyList());

        assertEquals(Arrays.asList("fido2-assert", "-G", "-h", DEVICE), runner.lastCommand);
    }

    @Test
    void hmacSecretRejectsShortSecret() {
        RecordingRunner runner = new RecordingRunner(Arrays.asList(
                "cdh", "rpid", "auth", "sig", base64(new byte[]{1, 2, 3})));
        LibFido2Token token = new LibFido2Token(DEVICE, "fido2-cred", "fido2-assert", runner);

        assertThrows(IOException.class,
                () -> token.hmacSecret(CREDENTIAL_ID, HMAC_SALT, Collections.<String>emptyList()));
    }

    @Test
    void hmacSecretRejectsAllZeroSecret() {
        RecordingRunner runner = new RecordingRunner(Arrays.asList(
                "cdh", "rpid", "auth", "sig", base64(new byte[32])));
        LibFido2Token token = new LibFido2Token(DEVICE, "fido2-cred", "fido2-assert", runner);

        assertThrows(IOException.class,
                () -> token.hmacSecret(CREDENTIAL_ID, HMAC_SALT, Collections.<String>emptyList()));
    }

    @Test
    void missingOutputLineIsRejected() {
        RecordingRunner runner = new RecordingRunner(Arrays.asList("cdh", "rpid"));
        LibFido2Token token = new LibFido2Token(DEVICE, "fido2-cred", "fido2-assert", runner);

        assertThrows(IOException.class, () -> token.registerCredential("bob"));
    }

    @Test
    void unstartableToolIsReported() {
        LibFido2Token token = new LibFido2Token(DEVICE,
                "definitely-not-a-real-fido2-tool-42", "fido2-assert");
        IOException e = assertThrows(IOException.class, () -> token.registerCredential("bob"));
        assertTrue(e.getMessage().contains("definitely-not-a-real-fido2-tool-42"), e.getMessage());
    }

    private static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static final class RecordingRunner implements Fido2CommandRunner {

        private final List<String> output;
        private List<String> lastCommand;
        private List<String> lastStdin;

        RecordingRunner(List<String> output) {
            this.output = output;
        }

        @Override
        public List<String> run(List<String> command, List<String> stdinLines) {
            this.lastCommand = command;
            this.lastStdin = stdinLines;
            return output;
        }
    }
}
