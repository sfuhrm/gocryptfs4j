/**
 * Module descriptor for gocryptfs4j-nio.
 *
 * <p>Compiled with {@code --release 9} and packaged as a multi-release JAR
 * ({@code META-INF/versions/9/module-info.class}), so the artifact stays a
 * plain Java 8 jar while exposing a real module on Java 9+.</p>
 */
module de.sfuhrm.gocryptfs4j.nio {
    requires transitive de.sfuhrm.gocryptfs4j.core;

    exports de.sfuhrm.gocryptfs4j.nio;

    provides java.nio.file.spi.FileSystemProvider
        with de.sfuhrm.gocryptfs4j.nio.GocryptFsProvider;
}
