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

    /** The POSIX view used to read and write the owner. */
    private final GocryptFsPosixFileAttributeView posix;

    /**
     * Creates the view.
     *
     * @param fs          the filesystem the path belongs to
     * @param path        the absolute plaintext path
     * @param followLinks whether symbolic links should be followed
     */
    GocryptFsOwnerFileAttributeView(GocryptFsFileSystem fs, GocryptFsPath path,
                                    boolean followLinks) {
        this.posix = new GocryptFsPosixFileAttributeView(fs, path, followLinks);
    }

    /**
     * Returns the view name.
     *
     * @return the string {@code "owner"}
     */
    @Override
    public String name() {
        return "owner";
    }

    /**
     * Returns the owner of the backing cipher file.
     *
     * @return the owner
     * @throws IOException on filesystem errors
     */
    @Override
    public UserPrincipal getOwner() throws IOException {
        return posix.getOwner();
    }

    /**
     * Sets the owner of the backing cipher file.
     *
     * @param owner the new owner
     * @throws IOException on filesystem errors
     */
    @Override
    public void setOwner(UserPrincipal owner) throws IOException {
        posix.setOwner(owner);
    }
}
