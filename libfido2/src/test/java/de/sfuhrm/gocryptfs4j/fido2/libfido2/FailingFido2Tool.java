package de.sfuhrm.gocryptfs4j.fido2.libfido2;

/**
 * A fake libfido2 tool that always fails, used to test that a non-zero exit
 * status and its standard error output are reported.
 */
public final class FailingFido2Tool {

    private FailingFido2Tool() {
    }

    /**
     * Writes a message to standard error and exits with status 3.
     *
     * @param args ignored
     */
    public static void main(String[] args) {
        System.err.println("boom: device exploded");
        System.exit(3);
    }
}
