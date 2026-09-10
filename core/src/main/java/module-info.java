/**
 * A pure Java implementation of the gocryptfs forward-mode on-disk format.
 *
 * <p>The public API consists of the {@code de.sfuhrm.gocryptfs4j.core} package
 * (the plain {@code GocryptFs} API). All other packages are internal
 * implementation details and are not exported.</p>
 */
module de.sfuhrm.gocryptfs4j.core {
    requires org.bouncycastle.provider;
    requires com.google.gson;

    exports de.sfuhrm.gocryptfs4j.core;

    opens de.sfuhrm.gocryptfs4j.config to com.google.gson;
}
