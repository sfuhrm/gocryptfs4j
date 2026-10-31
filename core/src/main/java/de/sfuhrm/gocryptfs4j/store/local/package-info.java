/**
 * The local-filesystem {@link de.sfuhrm.gocryptfs4j.store.CipherStore}
 * implementation.
 *
 * <p>{@link de.sfuhrm.gocryptfs4j.store.local.PathCipherStore} backs a gocryptfs
 * filesystem with an ordinary directory on a {@code java.nio.file} filesystem.
 * It is the default store used by the
 * {@code de.sfuhrm.gocryptfs4j.core.GocryptFs} {@code open}/{@code create}
 * factory methods that take a {@link java.nio.file.Path}.</p>
 */
@NullMarked
package de.sfuhrm.gocryptfs4j.store.local;

import org.jspecify.annotations.NullMarked;
