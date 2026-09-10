/**
 * The {@link java.nio.file.spi.FileSystemProvider} for gocryptfs cipher
 * directories, built on top of the {@code de.sfuhrm.gocryptfs4j.fs} API.
 */
module de.sfuhrm.gocryptfs4j.nio {
    requires transitive de.sfuhrm.gocryptfs4j.fs;

    exports de.sfuhrm.gocryptfs4j.nio;

    provides java.nio.file.spi.FileSystemProvider
            with de.sfuhrm.gocryptfs4j.nio.GocryptFsProvider;
}
