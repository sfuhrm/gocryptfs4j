package de.sfuhrm.gocryptfs4j.store;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;

/**
 * A {@link SeekableByteChannel} that additionally supports forcing buffered
 * content to stable storage, mirroring {@link java.nio.channels.FileChannel#force(boolean)}.
 *
 * <p>This is the channel type returned by {@link CipherStore#open(String, boolean)}.
 * Stores whose backing medium has no {@code force} primitive (for example object
 * stores or in-memory stores) implement {@link #force(boolean)} as a no-op.</p>
 */
public interface CipherChannel extends SeekableByteChannel {

    /**
     * Forces any updates to this channel's file to be written to the storage
     * device that contains it.
     *
     * @param metaData whether to also force the file's metadata (for example
     *                 size and modification time) in addition to its content
     * @throws IOException on storage errors
     */
    void force(boolean metaData) throws IOException;
}
