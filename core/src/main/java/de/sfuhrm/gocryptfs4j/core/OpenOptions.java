package de.sfuhrm.gocryptfs4j.core;

/**
 * Policy for opening an existing filesystem.
 *
 * <p>The feature flags in {@code gocryptfs.conf} are not covered by the
 * master-key AEAD, so an attacker with write access to the cipher directory can
 * change them. Some flag changes silently downgrade the on-disk format, most
 * importantly switching to plaintext names or dropping per-directory IVs
 * (which makes name encryption deterministic). By default {@link GocryptFs}
 * refuses to open such a config; a caller that really wants these modes must
 * opt in explicitly.</p>
 *
 * <p>Use {@link #defaults()} for the strict policy, or {@link #builder()} to
 * allow one of the downgrades:</p>
 *
 * <pre>{@code
 * OpenOptions options = OpenOptions.builder()
 *         .allowPlaintextNames(true)
 *         .build();
 * try (GocryptFs fs = GocryptFs.open(store, password, options)) {
 *     // ...
 * }
 * }</pre>
 */
public final class OpenOptions {

    /** The strict default policy, shared because instances are immutable. */
    private static final OpenOptions DEFAULTS = new OpenOptions(false, false);

    /** Whether configs with unencrypted names may be opened. */
    private final boolean allowPlaintextNames;

    /** Whether configs with deterministic name encryption may be opened. */
    private final boolean allowDeterministicNames;

    private OpenOptions(boolean allowPlaintextNames, boolean allowDeterministicNames) {
        this.allowPlaintextNames = allowPlaintextNames;
        this.allowDeterministicNames = allowDeterministicNames;
    }

    /**
     * Returns the strict default policy.
     *
     * <p>Plaintext names and deterministic names are rejected when opening.
     * Creating such a filesystem is still possible explicitly.</p>
     *
     * @return the default options
     */
    public static OpenOptions defaults() {
        return DEFAULTS;
    }

    /**
     * Returns a builder initialised with the strict defaults.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns whether plaintext names ({@code PlaintextNames}) may be opened.
     *
     * @return {@code true} if plaintext names are allowed
     */
    public boolean allowPlaintextNames() {
        return allowPlaintextNames;
    }

    /**
     * Returns whether deterministic name encryption may be opened.
     *
     * <p>This is the legacy mode that uses {@code EMENames} without
     * {@code DirIV}, so every directory uses the all-zero IV and equal names
     * encrypt to equal cipher names.</p>
     *
     * @return {@code true} if deterministic names are allowed
     */
    public boolean allowDeterministicNames() {
        return allowDeterministicNames;
    }

    /**
     * Returns a builder pre-populated with this policy.
     *
     * @return a new builder
     */
    public Builder toBuilder() {
        return new Builder()
                .allowPlaintextNames(allowPlaintextNames)
                .allowDeterministicNames(allowDeterministicNames);
    }

    /**
     * Builds an {@link OpenOptions} instance.
     */
    public static final class Builder {

        private boolean allowPlaintextNames;

        private boolean allowDeterministicNames;

        private Builder() {
        }

        /**
         * Sets whether configs with plaintext names may be opened.
         *
         * @param allow {@code true} to accept plaintext names
         * @return this builder
         */
        public Builder allowPlaintextNames(boolean allow) {
            this.allowPlaintextNames = allow;
            return this;
        }

        /**
         * Sets whether configs with deterministic name encryption may be
         * opened.
         *
         * @param allow {@code true} to accept deterministic names
         * @return this builder
         */
        public Builder allowDeterministicNames(boolean allow) {
            this.allowDeterministicNames = allow;
            return this;
        }

        /**
         * Builds the options.
         *
         * @return the options
         */
        public OpenOptions build() {
            return new OpenOptions(allowPlaintextNames, allowDeterministicNames);
        }
    }
}
