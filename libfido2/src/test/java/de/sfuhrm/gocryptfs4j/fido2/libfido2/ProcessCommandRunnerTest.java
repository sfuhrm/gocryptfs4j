package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the real {@link ProcessCommandRunner} by spawning a second JVM as a
 * stub FIDO2 tool. This covers process startup, standard-input plumbing,
 * standard-output parsing and non-zero exit handling without needing libfido2
 * installed or a security key attached.
 */
class ProcessCommandRunnerTest {

    private static final byte[] SECRET = new byte[32];

    static {
        for (int i = 0; i < SECRET.length; i++) {
            SECRET[i] = (byte) i;
        }
    }

    @Test
    void runsProcessAndParsesOutput() throws IOException {
        ProcessCommandRunner runner = new ProcessCommandRunner();

        List<String> output = runner.run(fakeToolCommand(), Arrays.asList("one", "two"));

        assertEquals(Arrays.asList("cdh", Fido2Token.RELYING_PARTY_ID, "auth-data", "sig",
                Base64.getEncoder().encodeToString(SECRET), ""), output);
    }

    @Test
    void tokenDrivesRealProcessRunner() throws IOException {
        LibFido2Token token = new LibFido2Token("/dev/fake", fakeToolCommand(),
                fakeToolCommand(), new ProcessCommandRunner());

        byte[] secret = token.hmacSecret(new byte[]{1, 2, 3}, new byte[32],
                Collections.<String>emptyList());

        assertArrayEquals(SECRET, secret);
    }

    @Test
    void nonZeroExitIncludesStandardError() {
        ProcessCommandRunner runner = new ProcessCommandRunner();
        List<String> command = new ArrayList<>(fakeToolCommand());
        command.add("fail");

        IOException e = assertThrows(IOException.class,
                () -> runner.run(command, Collections.<String>emptyList()));
        assertTrue(e.getMessage().contains("boom"), e.getMessage());
        assertTrue(e.getMessage().contains("3"), e.getMessage());
    }

    @Test
    void unstartableCommandIsReported() {
        ProcessCommandRunner runner = new ProcessCommandRunner();
        IOException e = assertThrows(IOException.class, () -> runner.run(
                Collections.singletonList("definitely-not-a-real-fido2-tool-42"),
                Collections.<String>emptyList()));
        assertTrue(e.getMessage().contains("definitely-not-a-real-fido2-tool-42"), e.getMessage());
    }

    private static List<String> fakeToolCommand() {
        String java = Paths.get(System.getProperty("java.home"), "bin", "java").toString();
        return Arrays.asList(java, "-cp", System.getProperty("java.class.path"),
                FakeTool.class.getName());
    }

    /** A stub FIDO2 tool: drains stdin, then prints a gocryptfs-shaped response. */
    public static final class FakeTool {

        /** Creates the stub tool (used reflectively by the spawned JVM). */
        public FakeTool() {
        }

        /**
         * Runs the stub tool.
         *
         * @param args the FIDO2 arguments appended by the token, ignored except for {@code fail}
         * @throws IOException on I/O errors
         */
        public static void main(String[] args) throws IOException {
            drain(System.in);
            if (Arrays.asList(args).contains("fail")) {
                System.err.println("boom");
                System.exit(3);
            }
            PrintStream out = System.out;
            out.println("cdh");
            out.println(Fido2Token.RELYING_PARTY_ID);
            out.println("auth-data");
            out.println("sig");
            out.println(Base64.getEncoder().encodeToString(SECRET));
        }
    }

    private static void drain(InputStream in) throws IOException {
        byte[] buffer = new byte[4096];
        while (in.read(buffer) != -1) {
            // discard the token's protocol input
        }
    }
}
