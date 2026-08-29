package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/** A {@link DirectoryStream} over a decrypted directory. */
final class GocryptFsDirectoryStream implements DirectoryStream<Path> {

    private final List<Path> entries;
    private volatile boolean closed;

    GocryptFsDirectoryStream(List<Path> entries) {
        this.entries = new ArrayList<>(entries);
    }

    @Override
    public Iterator<Path> iterator() {
        if (closed) {
            throw new IllegalStateException("directory stream is closed");
        }
        return entries.iterator();
    }

    @Override
    public void close() throws IOException {
        closed = true;
    }
}
