package de.sfuhrm.gocryptfs4j.config;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;

import java.lang.reflect.Type;
import java.util.Base64;
import java.util.List;

/**
 * The FIDO2 parameters stored in the {@code FIDO2} object of
 * {@code gocryptfs.conf}.
 *
 * <p>This mirrors gocryptfs's {@code FIDO2Params}: the credential ID, the random
 * salt fed to the FIDO2 {@code hmac-secret} extension and the optional
 * {@code fido2-assert} options. All byte arrays are encoded as standard base64,
 * exactly like Go's {@code encoding/json} encodes {@code []byte}.</p>
 */
public final class Fido2Params {

    /** Length in bytes of the random HMAC-secret salt. */
    public static final int HMAC_SALT_LEN = 32;

    /** Base64-encoded FIDO2 credential ID. */
    @SerializedName("CredentialID")
    @JsonAdapter(Base64ByteArrayAdapter.class)
    public byte[] credentialId;

    /** Base64-encoded salt for the FIDO2 {@code hmac-secret} extension. */
    @SerializedName("HMACSalt")
    @JsonAdapter(Base64ByteArrayAdapter.class)
    public byte[] hmacSalt;

    /** Options to pass to the FIDO2 assertion, or {@code null} if unused. */
    @SerializedName("AssertOptions")
    public List<String> assertOptions;

    /** Creates an empty parameter object (used by Gson). */
    public Fido2Params() {
    }

    /**
     * Creates a parameter object.
     *
     * @param credentialId  the raw credential ID
     * @param hmacSalt      the raw HMAC-secret salt
     * @param assertOptions the assertion options, or {@code null}
     * @throws NullPointerException if {@code credentialId} or {@code hmacSalt} is {@code null}
     */
    public Fido2Params(byte[] credentialId, byte[] hmacSalt, List<String> assertOptions) {
        this.credentialId = credentialId.clone();
        this.hmacSalt = hmacSalt.clone();
        this.assertOptions = assertOptions;
    }

    /**
     * Gson adapter that encodes {@code byte[]} as a base64 JSON string, matching
     * Go's {@code encoding/json} representation of {@code []byte}.
     */
    public static final class Base64ByteArrayAdapter
            implements JsonSerializer<byte[]>, JsonDeserializer<byte[]> {

        /** Creates the adapter (used by Gson). */
        public Base64ByteArrayAdapter() {
        }

        @Override
        public JsonElement serialize(byte[] src, Type type, JsonSerializationContext context) {
            if (src == null) {
                return null;
            }
            return new JsonPrimitive(Base64.getEncoder().encodeToString(src));
        }

        @Override
        public byte[] deserialize(JsonElement json, Type type, JsonDeserializationContext context)
                throws JsonParseException {
            if (json == null || json.isJsonNull()) {
                return null;
            }
            return Base64.getDecoder().decode(json.getAsString());
        }
    }
}
