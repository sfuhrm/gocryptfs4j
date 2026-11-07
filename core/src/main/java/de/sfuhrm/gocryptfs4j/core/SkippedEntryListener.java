package de.sfuhrm.gocryptfs4j.core;

import java.io.IOException;

/**
 * Receives the entries that a directory listing could not decrypt or resolve.
 *
 * <p>By default {@link GocryptFs#list(String)} silently omits corrupt entries,
 * matching a gocryptfs mount. A listener makes those omissions visible without
 * changing the default behaviour. Throw an {@link IOException} from
 * {@link #onSkippedEntry(String, IOException)} to abort the listing instead,
 * which turns a lenient listing into a strict one.</p>
 */
@FunctionalInterface
public interface SkippedEntryListener {

    /**
     * Called once for every entry a listing skips.
     *
     * @param cipherName the ciphertext name of the skipped entry
     * @param reason     why the entry was skipped
     * @throws IOException to abort the listing
     */
    void onSkippedEntry(String cipherName, IOException reason) throws IOException;
}
