package de.sfuhrm.gocryptfs4j.store;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

/**
 * A factory for a {@link CipherStore}, discovered by {@link java.util.ServiceLoader}
 * and selected by URI scheme.
 *
 * <p>Implementations are registered via
 * {@code META-INF/services/de.sfuhrm.gocryptfs4j.store.CipherStoreProvider} and
 * look up the store for their {@link #scheme() scheme} in {@link #newStore(URI, Map)}.
 * {@link CipherStores} resolves a URI to a store by matching its scheme against
 * the registered providers, in the same way
 * {@code java.nio.file.spi.FileSystemProvider} resolves filesystems.</p>
 *
 * <h2>Implementing a remote backend</h2>
 *
 * <p>The gocryptfs on-disk format needs only a small set of storage primitives
 * &mdash; named blobs for the control files ({@code gocryptfs.conf},
 * {@code gocryptfs.diriv}, long-name {@code .name} files) and random-access
 * file content. A remote backend such as an object store (S3) or WebDAV maps
 * each ciphertext name to an object key and implements the primitive methods
 * accordingly:</p>
 *
 * <ul>
 *   <li>{@link CipherStore#readSmall} / {@link CipherStore#writeSmall} &mdash; a
 *       bounded whole-object GET / PUT of a control blob.</li>
 *   <li>{@link CipherStore#list} / {@link CipherStore#stat} &mdash; a
 *       prefix listing, with directories emulated either by delimiter grouping
 *       (S3 {@code delimiter=/}) or by explicit directory marker objects.</li>
 *   <li>{@link CipherStore#open} &mdash; the critical piece. Object stores
 *       cannot update the middle of a blob, so return a {@link java.nio.channels.SeekableByteChannel}
 *       that buffers the whole object locally and uploads it on {@code close()}.
 *       This lets the encrypted-file layer do its block-wise read-modify-write
 *       unchanged; the cost is a whole-object transfer per write, exactly like
 *       rclone's {@code crypt} backend. A store with range GET and multipart
 *       upload can later optimize behind the same interface.</li>
 *   <li>{@link CipherStore#rename} &mdash; emulate as copy + delete when the
 *       store has no native move (S3); WebDAV's {@code MOVE} maps directly.</li>
 *   <li>{@link CipherStore#createSymlink} / {@link CipherStore#readSymlink}
 *       &mdash; unsupported on most object stores; throw
 *       {@link UnsupportedOperationException}, or store the target in a
 *       marker object if the backend can.</li>
 * </ul>
 *
 * <p>The in-memory {@code de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore}
 * is a complete, dependency-free reference implementation of this pattern and
 * doubles as a test fixture.</p>
 */
public interface CipherStoreProvider {

    /**
     * Returns the URI scheme this provider handles, for example {@code "memory"}
     * or {@code "s3"}.
     *
     * @return the URI scheme
     */
    String scheme();

    /**
     * Opens (or creates) the {@link CipherStore} identified by {@code uri}.
     *
     * <p>The {@code env} map carries backend-specific options such as
     * credentials, region or endpoint; providers document their own keys. A
     * provider may create the underlying store on demand.</p>
     *
     * @param uri the URI identifying the store
     * @param env backend-specific options, or {@code null} for defaults
     * @return the store
     * @throws IOException if the store cannot be created or reached
     */
    CipherStore newStore(URI uri, Map<String, ?> env) throws IOException;
}
