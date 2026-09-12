package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for {@link LibFido2Token} that spawn real subprocesses.
 *
 * <p>The main tests use a fake tool implemented in Java
 * ({@link FakeFido2Tool}) so they run on any operating system without a FIDO2
 * device. {@link #againstRealDevice()} additionally exercises real
 * {@code fido2-cred}/{@code fido2-assert} commands when the environment variable
 * {@code GOCRYPTFS4J_FIDO2_DEVICE} points at an actual device; otherwise it is
 * skipped.</p>
 */
class LibFido2TokenIT {

    @Test
    void drivesRealSubprocesses() throws Exception {
        List<String> tool = fakeToolCommand(FakeFido2Tool.class);
        LibFido2Token token = new LibFido2Token("/dev/fake", tool, tool, new ProcessCommandRunner());

        byte[] credentialId = token.registerCredential("alice");
        assertArrayEquals(FakeFido2Tool.CREDENTIAL_ID, credentialId);

        byte[] hmacSalt = new byte[32];
        for (int i = 0; i < hmacSalt.length; i++) {
            hmacSalt[i] = (byte) i;
        }
        byte[] secret = token.hmacSecret(credentialId, hmacSalt, Arrays.asList("uv=false"));
        assertArrayEquals(FakeFido2Tool.expectedSecret(credentialId, hmacSalt), secret);
    }

    @Test
    void reportsNonZeroExitWithStderr() {
        List<String> tool = fakeToolCommand(FailingFido2Tool.class);
        LibFido2Token token = new LibFido2Token("/dev/fake", tool, tool, new ProcessCommandRunner());

        IOException e = assertThrows(IOException.class, () -> token.registerCredential("bob"));
        assertTrue(e.getMessage().contains("boom"), e.getMessage());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "GOCRYPTFS4J_FIDO2_DEVICE", matches = ".+")
    void againstRealDevice() throws Exception {
        String device = System.getenv("GOCRYPTFS4J_FIDO2_DEVICE");
        LibFido2Token token = new LibFido2Token(device);

        byte[] credentialId = token.registerCredential("gocryptfs4j-it");
        assertTrue(credentialId.length > 0, "expected a credential id from the real device");

        byte[] secret = token.hmacSecret(credentialId, new byte[32], Collections.<String>emptyList());
        assertTrue(secret.length >= 32, "expected an HMAC secret of at least 32 bytes");
    }

    private static List<String> fakeToolCommand(Class<?> toolClass) {
        String java = Paths.get(System.getProperty("java.home"), "bin",
                isWindows() ? "java.exe" : "java").toString();
        String classpath = System.getProperty("surefire.test.class.path",
                System.getProperty("java.class.path"));
        return Arrays.asList(java, "-cp", classpath, toolClass.getName());
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }
}
