/**
 * A pure Java implementation of the gocryptfs forward-mode on-disk format.
 *
 * <p>The public API consists of the {@code de.sfuhrm.gocryptfs4j.fs} package
 * (the plain {@code GocryptFs} API) and the
 * {@code de.sfuhrm.gocryptfs4j.nio} package (the
 * {@link java.nio.file.spi.FileSystemProvider}). All other packages are
 * internal implementation details and are not exported.</p>
 */
module de.sfuhrm.gocryptfs4j {
    requires org.bouncycastle.provider;
    requires com.google.gson;

    exports de.sfuhrm.gocryptfs4j.fs;
    exports de.sfuhrm.gocryptfs4j.nio;

    opens de.sfuhrm.gocryptfs4j.config to com.google.gson;

    provides java.nio.file.spi.FileSystemProvider
            with de.sfuhrm.gocryptfs4j.nio.GocryptFsProvider;
}
