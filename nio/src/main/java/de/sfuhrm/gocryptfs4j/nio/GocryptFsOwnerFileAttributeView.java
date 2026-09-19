package de.sfuhrm.gocryptfs4j.nio;

import java.io.IOException;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.UserPrincipal;

/**
 * A {@link FileOwnerAttributeView} for a gocryptfs plaintext path.
 *
 * <p>Ownership is stored on the backing cipher file; see
 * {@link GocryptFsPosixFileAttributeView}.</p>
 */
final class GocryptFsOwnerFileAttributeView implements FileOwnerAttributeView {

    private final GocryptFsPosixFileAttributeView posix;

    GocryptFsOwnerFileAttributeView(GocryptFsFileSystem fs, GocryptFsPath path,
                                    boolean followLinks) {
        this.posix = new GocryptFsPosixFileAttributeView(fs, path, followLinks);
    }

    @Override
    public String name() {
        return "owner";
    }

    @Override
    public UserPrincipal getOwner() throws IOException {
        return posix.getOwner();
    }

    @Override
    public void setOwner(UserPrincipal owner) throws IOException {
        posix.setOwner(owner);
    }
}
