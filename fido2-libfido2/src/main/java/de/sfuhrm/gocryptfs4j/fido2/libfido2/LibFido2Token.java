package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import de.sfuhrm.gocryptfs4j.fido2.Fido2Token;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * A {@link Fido2Token} implementation that drives the libfido2 command-line
 * tools {@code fido2-cred} and {@code fido2-assert}.
 *
 * <p>The invocation and input/output format replicate gocryptfs's
 * {@code internal/fido2} package, so credentials created here can be used by
 * gocryptfs and vice versa. The tools must be installed and on the
 * {@code PATH} (or their absolute paths passed to
 * {@link #LibFido2Token(String, String, String)}).</p>
 *
 * <p>Registration runs {@code fido2-cred -M -h <device>} with the client data
 * hash, relying-party ID, user name and a random user id. Assertions run
 * {@code fido2-assert -G -h [-t option ...] <device>} with the client data hash,
 * relying-party ID, credential id and HMAC salt; the fifth output line is the
 * HMAC secret. Set {@code -t pin=true} via the assertion options to request PIN
 * entry. Because the tools read the PIN from the terminal if one is available,
 * a PIN-protected token works when gocryptfs4j runs interactively.</p>
 */
public final class LibFido2Token implements Fido2Token {

    private static final String CRED_TOOL = "fido2-cred";
    private static final String ASSERT_TOOL = "fido2-assert";

    /** Length of the random client data hash sent to the tools. */
    private static final int CLIENT_DATA_HASH_LEN = 32;

    /** Length of the random user id used during registration. */
    private static final int USER_ID_LEN = 32;

    /** Minimum accepted length of the HMAC secret, as required by gocryptfs. */
    private static final int MIN_SECRET_LEN = 32;

    /**
     * Index of the credential id in the output of {@code fido2-cred -M} and of
     * the HMAC secret in the output of {@code fido2-assert -G -h} for a
     * non-resident credential.
     */
    private static final int OUTPUT_SECRET_LINE = 4;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String device;
    private final List<String> credCommand;
    private final List<String> assertCommand;
    private final Fido2CommandRunner runner;

    /**
     * Creates a token that uses {@code fido2-cred} and {@code fido2-assert} from
     * the {@code PATH}.
     *
     * @param device the FIDO2 device path passed to the tools, for example
     *               {@code /dev/hidraw5}
     * @throws NullPointerException if {@code device} is {@code null}
     */
    public LibFido2Token(String device) {
        this(device, CRED_TOOL, ASSERT_TOOL, new ProcessCommandRunner());
    }

    /**
     * Creates a token that uses the given tool executables.
     *
     * @param device      the FIDO2 device path passed to the tools
     * @param credTool    the path or name of the {@code fido2-cred} executable
     * @param assertTool  the path or name of the {@code fido2-assert} executable
     * @throws NullPointerException if any argument is {@code null}
     */
    public LibFido2Token(String device, String credTool, String assertTool) {
        this(device, credTool, assertTool, new ProcessCommandRunner());
    }

    LibFido2Token(String device, String credTool, String assertTool, Fido2CommandRunner runner) {
        this(device, Arrays.asList(credTool), Arrays.asList(assertTool), runner);
    }

    /**
     * Creates a token whose tools are given as a full command prefix. The FIDO2
     * arguments ({@code -M -h <device>} or {@code -G -h ... <device>}) are
     * appended to the prefix. Primarily a seam for tests that want to point at a
     * fake executable such as another JVM.
     */
    LibFido2Token(String device, List<String> credCommand, List<String> assertCommand,
                  Fido2CommandRunner runner) {
        this.device = Objects.requireNonNull(device, "device");
        this.credCommand = requireCommand(credCommand, "credCommand");
        this.assertCommand = requireCommand(assertCommand, "assertCommand");
        this.runner = Objects.requireNonNull(runner, "runner");
    }

    private static List<String> requireCommand(List<String> command, String name) {
        Objects.requireNonNull(command, name);
        if (command.isEmpty()) {
            throw new IllegalArgumentException(name + " must not be empty");
        }
        return new ArrayList<>(command);
    }

    @Override
    public byte[] registerCredential(String userName) throws IOException {
        Objects.requireNonNull(userName, "userName");
        List<String> command = new ArrayList<>(credCommand);
        command.add("-M");
        command.add("-h");
        command.add(device);
        List<String> input = Arrays.asList(
                base64(randomBytes(CLIENT_DATA_HASH_LEN)),
                RELYING_PARTY_ID,
                userName,
                base64(randomBytes(USER_ID_LEN)));
        List<String> output = runner.run(command, input);
        return decodeOutput(output, OUTPUT_SECRET_LINE, "credential id");
    }

    @Override
    public byte[] hmacSecret(byte[] credentialId, byte[] hmacSalt, List<String> assertOptions)
            throws IOException {
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(hmacSalt, "hmacSalt");
        Objects.requireNonNull(assertOptions, "assertOptions");
        List<String> command = new ArrayList<>(assertCommand);
        command.add("-G");
        command.add("-h");
        for (String option : assertOptions) {
            command.add("-t");
            command.add(option);
        }
        command.add(device);
        List<String> input = Arrays.asList(
                base64(randomBytes(CLIENT_DATA_HASH_LEN)),
                RELYING_PARTY_ID,
                base64(credentialId),
                base64(hmacSalt));
        List<String> output = runner.run(command, input);
        byte[] secret = decodeOutput(output, OUTPUT_SECRET_LINE, "hmac secret");
        if (secret.length < MIN_SECRET_LEN) {
            throw new IOException("FIDO2 HMAC secret too short ("
                    + secret.length + " bytes, want at least " + MIN_SECRET_LEN + ")");
        }
        if (isAllZero(secret)) {
            throw new IOException("FIDO2 HMAC secret is all zero");
        }
        return secret;
    }

    private static byte[] decodeOutput(List<String> output, int line, String what) throws IOException {
        if (output.size() <= line) {
            throw new IOException("unexpected FIDO2 tool output: missing " + what);
        }
        try {
            return Base64.getDecoder().decode(output.get(line));
        } catch (IllegalArgumentException e) {
            throw new IOException("invalid base64 in FIDO2 " + what, e);
        }
    }

    private static boolean isAllZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static String base64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
