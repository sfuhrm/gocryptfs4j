/**
 * The storage SPI for gocryptfs4j.
 *
 * <p>{@link de.sfuhrm.gocryptfs4j.store.CipherStore} abstracts the ciphertext
 * side of a gocryptfs filesystem &mdash; a set of named blobs (the
 * {@code gocryptfs.conf}, per-directory {@code gocryptfs.diriv} files, long-name
 * support files and the encrypted file contents) plus a small set of metadata
 * operations. {@link de.sfuhrm.gocryptfs4j.core.GocryptFs} performs all name and
 * content encryption on top of a {@link de.sfuhrm.gocryptfs4j.store.CipherStore}
 * and never touches {@code java.nio.file} directly, so the same crypto code
 * works against the local filesystem (see
 * {@code de.sfuhrm.gocryptfs4j.store.local.PathCipherStore}) or against a remote
 * store such as an object store, WebDAV or SFTP.</p>
 */
@NullMarked
package de.sfuhrm.gocryptfs4j.store;

import org.jspecify.annotations.NullMarked;
