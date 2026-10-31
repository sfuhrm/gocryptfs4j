package de.sfuhrm.gocryptfs4j.store.tracking;

import de.sfuhrm.gocryptfs4j.core.GocryptFs;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies store ownership: {@link GocryptFs} closes stores it creates itself
 * from a URI, but leaves caller-supplied stores open.
 */
class StoreOwnershipTest {

    @BeforeEach
    void resetProvider() {
        TrackingCipherStoreProvider.reset();
    }

    @Test
    void createViaUriClosesOwnedStoreOnClose() throws IOException {
        try (GocryptFs fs = GocryptFs.create(URI.create("tracking:///"), Collections.emptyMap(),
                "pw".toCharArray())) {
            fs.createFile("/f");
        }

        TrackingCipherStore store = TrackingCipherStoreProvider.created().get(0);
        assertTrue(store.isClosed(), "URI-created store must be closed by GocryptFs.close()");
    }

    @Test
    void openViaUriClosesOwnedStoreOnClose() throws IOException {
        // Seed a config in a store we still own, so it is not closed yet.
        TrackingCipherStore seeded = new TrackingCipherStore();
        try (GocryptFs fs = GocryptFs.create(seeded, "pw".toCharArray())) {
            fs.createFile("/f");
        }
        assertFalse(seeded.isClosed(), "caller-supplied store must not be closed");

        // Hand the same store out under the URI scheme, so open() owns it.
        TrackingCipherStoreProvider.setNext(seeded);
        try (GocryptFs fs = GocryptFs.open(URI.create("tracking:///"), Collections.emptyMap(),
                "pw".toCharArray())) {
            assertEquals(1, fs.list("/").size());
        }
        assertTrue(seeded.isClosed(), "URI-created store must be closed by GocryptFs.close()");
    }

    @Test
    void callerSuppliedStoreIsNotClosed() throws IOException {
        TrackingCipherStore store = new TrackingCipherStore();
        try (GocryptFs fs = GocryptFs.create(store, "pw".toCharArray())) {
            fs.createFile("/f");
        }
        assertFalse(store.isClosed(), "caller-supplied store must not be closed");
    }

    @Test
    void failedOpenViaUriClosesStore() {
        assertThrows(IOException.class,
                () -> GocryptFs.open(URI.create("tracking:///"), Collections.emptyMap(),
                        "pw".toCharArray()));

        TrackingCipherStore store = TrackingCipherStoreProvider.created().get(0);
        assertTrue(store.isClosed(), "a store created for a failed open must be closed");
    }
}
