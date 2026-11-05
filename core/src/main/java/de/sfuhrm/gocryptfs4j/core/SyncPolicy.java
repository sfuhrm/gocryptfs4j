package de.sfuhrm.gocryptfs4j.core;

/**
 * Controls when buffered plaintext is written through to the cipher file.
 *
 * <p>Writes are buffered in a single plaintext block per open file. The policy
 * decides when that block is flushed, trading the visibility and durability of
 * a completed write against write batching.</p>
 */
public enum SyncPolicy {

    /**
     * Keep the block buffered until the last handle on the file is closed.
     * A completed write may not be visible to another process or survive a
     * crash while another handle keeps the file open.
     */
    NONE,

    /**
     * Flush the buffered block and force it to storage whenever a channel is
     * closed, even when other handles on the same file remain open.
     */
    ON_CLOSE,

    /**
     * Flush and force the buffered block after every write, in addition to
     * doing so when a channel is closed.
     */
    ALWAYS;

    /**
     * Returns {@code policy}, or {@link #ON_CLOSE} when it is {@code null}.
     *
     * @param policy the policy, possibly {@code null}
     * @return the effective policy
     */
    static SyncPolicy orDefault(SyncPolicy policy) {
        return policy == null ? ON_CLOSE : policy;
    }
}
