package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;
import java.io.OutputStream;

/**
 * An output stream whose pending write can be discarded instead of committed.
 *
 * <p>The streams returned by {@link GocryptFs#openWrite(String)} stage their
 * content in a hidden temporary file and replace the target only on a
 * successful {@link #close()}. If a producer fails partway through, it should
 * call {@link #abort()} rather than {@link #close()}, for example from a
 * {@code catch} block, so the partial content is removed and the previous file
 * is left untouched.</p>
 *
 * <p>As a safety net, a stream that observes a write, flush or close failure
 * aborts itself instead of committing the partial result.</p>
 */
public abstract class AbortableOutputStream extends OutputStream {

    /**
     * Discards the pending write and releases its resources.
     *
     * <p>After this call the stream is closed and the target file is unchanged.
     * Calling this method more than once, or after a successful
     * {@link #close()}, has no effect.</p>
     *
     * @throws IOException on filesystem errors while removing the staged data
     */
    public abstract void abort() throws IOException;
}
