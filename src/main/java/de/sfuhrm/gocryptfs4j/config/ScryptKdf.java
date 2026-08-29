package de.sfuhrm.gocryptfs4j.config;

import com.google.gson.annotations.SerializedName;

/**
 * The scrypt parameters stored in {@code gocryptfs.conf}.
 */
public final class ScryptKdf {

    /** Base64-encoded salt. */
    @SerializedName("Salt")
    public String salt;

    /** CPU/memory cost parameter (2^LogN). */
    @SerializedName("N")
    public int n;

    /** Block size parameter. */
    @SerializedName("R")
    public int r;

    /** Parallelization parameter. */
    @SerializedName("P")
    public int p;

    /** Output key length in bytes. */
    @SerializedName("KeyLen")
    public int keyLen;
}
