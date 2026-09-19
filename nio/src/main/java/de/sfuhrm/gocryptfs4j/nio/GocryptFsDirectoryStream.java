package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * A {@link DirectoryStream} over a decrypted directory.
 *
 * <p>The directory entries are read eagerly when the stream is created. The
 * iterator can be obtained only once, as required by {@link DirectoryStream}.</p>
 */
final class GocryptFsDirectoryStream implements DirectoryStream<Path> {

    /** The entries of the directory, in listing order. */
    private final List<Path> entries;

    /** Whether the stream has been closed. */
    private volatile boolean closed;

    /** Whether an iterator has already been handed out. */
    private boolean iteratorObtained;

    /**
     * Creates the stream.
     *
     * @param entries the entries of the directory
     */
    GocryptFsDirectoryStream(List<Path> entries) {
        this.entries = new ArrayList<>(entries);
    }

    /**
     * Returns an iterator over the directory entries. The iterator may be
     * obtained only once.
     *
     * @return an iterator over the entries
     * @throws IllegalStateException if the stream is closed or an iterator was already obtained
     */
    @Override
    public synchronized Iterator<Path> iterator() {
        if (closed) {
            throw new IllegalStateException("directory stream is closed");
        }
        if (iteratorObtained) {
            throw new IllegalStateException("iterator can only be obtained once");
        }
        iteratorObtained = true;
        return entries.iterator();
    }

    /**
     * Closes the stream.
     *
     * @throws IOException if closing fails; this implementation never throws
     */
    @Override
    public void close() throws IOException {
        closed = true;
    }
}
