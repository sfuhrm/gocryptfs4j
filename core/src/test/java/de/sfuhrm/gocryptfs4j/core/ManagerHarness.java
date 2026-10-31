package de.sfuhrm.gocryptfs4j.core;

import de.sfuhrm.gocryptfs4j.crypto.AesBlockCipher;
import de.sfuhrm.gocryptfs4j.crypto.Constants;
import de.sfuhrm.gocryptfs4j.crypto.ContentEnc;
import de.sfuhrm.gocryptfs4j.crypto.Eme;
import de.sfuhrm.gocryptfs4j.crypto.Keys;
import de.sfuhrm.gocryptfs4j.names.NameTransform;
import de.sfuhrm.gocryptfs4j.store.CipherStore;
import de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore;

import java.io.IOException;

/**
 * Builds a fully wired set of the {@code GocryptFs} collaborators over an
 * in-memory {@link CipherStore}, so the individual managers can be exercised
 * directly rather than only through the {@link GocryptFs} facade.
 */
final class ManagerHarness {

    /** The ciphertext-side store. */
    final CipherStore store;

    /** The name manager. */
    final NameManager nameManager;

    /** The directory manager. */
    final DirectoryManager directoryManager;

    /** The path resolver. */
    final PathResolver pathResolver;

    /** The file manager. */
    final FileManager fileManager;

    /** The content-encryption helper. */
    final ContentEnc contentEnc;

    /** Whether the harness uses unencrypted file names. */
    final boolean plaintextNames;

    /** Whether the harness uses deterministic (no per-directory IV) names. */
    final boolean deterministicNames;

    /**
     * Creates a harness over a fresh in-memory store.
     *
     * @param plaintextNames     whether file names are stored unencrypted
     * @param deterministicNames whether deterministic name encryption is used
     */
    private ManagerHarness(boolean plaintextNames, boolean deterministicNames) throws IOException {
        this.store = new MapCipherStore();
        this.plaintextNames = plaintextNames;
        this.deterministicNames = deterministicNames;

        Eme eme = new Eme(new AesBlockCipher(Keys.randomBytes(Constants.KEY_LEN)));
        this.contentEnc = new ContentEnc(Keys.randomBytes(Constants.KEY_LEN),
                Constants.DEFAULT_IV_BITS / 8);
        NameTransform nameTransform = new NameTransform(eme, true, Constants.NAME_MAX, false,
                deterministicNames);

        this.nameManager = new NameManager(nameTransform, plaintextNames, store);
        this.directoryManager = new DirectoryManager(store, store.root(), plaintextNames,
                deterministicNames, nameTransform, contentEnc, nameManager);
        this.pathResolver = new PathResolver(store, store.root(), plaintextNames,
                nameManager, directoryManager);
        this.fileManager = new FileManager(store, contentEnc, nameTransform, plaintextNames,
                nameManager, directoryManager, pathResolver);

        if (!plaintextNames && !deterministicNames) {
            directoryManager.writeDirIV(store.root());
        }
    }

    /**
     * Returns a harness with encrypted (per-directory IV) names.
     *
     * @return the harness
     */
    static ManagerHarness encrypted() throws IOException {
        return new ManagerHarness(false, false);
    }

    /**
     * Returns a harness with unencrypted (plaintext) names.
     *
     * @return the harness
     */
    static ManagerHarness plaintext() throws IOException {
        return new ManagerHarness(true, false);
    }

    /**
     * Returns a harness with deterministic (no per-directory IV) name encryption.
     *
     * @return the harness
     */
    static ManagerHarness deterministic() throws IOException {
        return new ManagerHarness(false, true);
    }
}
