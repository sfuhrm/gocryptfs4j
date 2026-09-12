package de.sfuhrm.gocryptfs4j.config;

import com.google.gson.JsonNull;
import com.google.gson.JsonPrimitive;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Fido2ParamsTest {

    private final Fido2Params.Base64ByteArrayAdapter adapter =
            new Fido2Params.Base64ByteArrayAdapter();

    @Test
    void adapterSerializesNullAndBytes() {
        assertNull(adapter.serialize(null, byte[].class, null));

        JsonPrimitive json = (JsonPrimitive) adapter.serialize(
                new byte[]{1, 2, 3}, byte[].class, null);
        assertEquals(Base64.getEncoder().encodeToString(new byte[]{1, 2, 3}), json.getAsString());
    }

    @Test
    void adapterDeserializesNullAndBytes() {
        assertNull(adapter.deserialize(null, byte[].class, null));
        assertNull(adapter.deserialize(JsonNull.INSTANCE, byte[].class, null));

        byte[] decoded = adapter.deserialize(new JsonPrimitive(
                Base64.getEncoder().encodeToString(new byte[]{1, 2, 3})), byte[].class, null);
        assertArrayEquals(new byte[]{1, 2, 3}, decoded);
    }

    @Test
    void assertOptionsAreCopiedAndUnmodifiable() {
        List<String> options = new ArrayList<>();
        options.add("uv=false");
        Fido2Params params = new Fido2Params(new byte[]{1}, new byte[]{2}, options);

        options.add("pin=true");
        assertEquals(Collections.singletonList("uv=false"), params.assertOptions);
        assertThrows(UnsupportedOperationException.class, () -> params.assertOptions.add("x"));
        assertNull(new Fido2Params(new byte[]{1}, new byte[]{2}, null).assertOptions);
    }
}
