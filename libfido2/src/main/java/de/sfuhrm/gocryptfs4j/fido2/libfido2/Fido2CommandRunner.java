package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import java.io.IOException;
import java.util.List;

/**
 * Runs a FIDO2 tool with the given command line and standard input, returning
 * its raw standard output.
 *
 * <p>The output is kept as bytes rather than a {@link String} so that the
 * caller can decode the HMAC secret without leaving behind an immutable copy
 * that cannot be wiped. This is an internal seam that keeps
 * {@link LibFido2Token} testable without spawning processes.</p>
 */
interface Fido2CommandRunner {

    /**
     * Runs {@code command}, writes {@code stdinLines} to its standard input
     * (each followed by a newline) and returns the raw standard output.
     *
     * @param command    the command and its arguments
     * @param stdinLines the lines to write to the tool's standard input
     * @return the standard output bytes, never {@code null}
     * @throws IOException if the tool cannot be started or exits non-zero
     */
    byte[] run(List<String> command, List<String> stdinLines) throws IOException;
}
