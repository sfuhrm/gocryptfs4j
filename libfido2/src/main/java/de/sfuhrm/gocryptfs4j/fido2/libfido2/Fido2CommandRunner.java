package de.sfuhrm.gocryptfs4j.fido2.libfido2;

import java.io.IOException;
import java.util.List;

/**
 * Runs a FIDO2 tool with the given command line and standard input, returning
 * the lines written on standard output.
 *
 * <p>This is an internal seam that keeps {@link LibFido2Token} testable without
 * spawning processes.</p>
 */
interface Fido2CommandRunner {

    /**
     * Runs {@code command}, writes {@code stdinLines} to its standard input
     * (each followed by a newline) and returns the standard output split into
     * lines.
     *
     * @param command    the command and its arguments
     * @param stdinLines the lines to write to the tool's standard input
     * @return the standard output split on {@code '\n'}, never {@code null}
     * @throws IOException if the tool cannot be started or exits non-zero
     */
    List<String> run(List<String> command, List<String> stdinLines) throws IOException;
}
