/**
 * An in-memory {@link de.sfuhrm.gocryptfs4j.store.CipherStore} reference
 * implementation and test fixture.
 *
 * <p>{@link de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore} stores the whole
 * ciphertext tree in {@code Map}s, with no external dependencies. It is the
 * canonical example of how a non-local backend implements
 * {@link de.sfuhrm.gocryptfs4j.store.CipherStore}, and is used by tests to prove
 * that {@code GocryptFs} is store-agnostic. {@link MapCipherStoreProvider}
 * exposes it under the {@code memory} URI scheme.</p>
 */
@NullMarked
package de.sfuhrm.gocryptfs4j.store.memory;

import org.jspecify.annotations.NullMarked;
