package de.sfuhrm.gocryptfs4j.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class GocryptFsTest {

    @TempDir
    Path tmp;

    @Test
    void createWriteReadListAndReopen() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] secret = "hello gocryptfs".getBytes(StandardCharsets.UTF_8);
        byte[] big = new byte[100_000];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) (i * 31);
        }

        try (GocryptFs fs = GocryptFs.create(cipherDir, "secretpw".toCharArray())) {
            fs.mkdir("/docs");
            fs.createFile("/docs/hello.txt");
            fs.write("/docs/hello.txt", 0, secret);
            fs.createFile("/big.bin");
            fs.write("/big.bin", 0, big);

            // verify content via readAll
            assertArrayEquals(secret, fs.readAll("/docs/hello.txt"));
            assertArrayEquals(big, fs.readAll("/big.bin"));

            // verify listing
            Set<String> root = fs.list("/").stream()
                    .map(DirEntry::plainName).collect(Collectors.toSet());
            assertEquals(Set.of("docs", "big.bin"), root);

            Set<String> docs = fs.list("/docs").stream()
                    .map(DirEntry::plainName).collect(Collectors.toSet());
            assertEquals(Set.of("hello.txt"), docs);

            // verify size
            assertEquals(secret.length, fs.size("/docs/hello.txt"));
            assertEquals(big.length, fs.size("/big.bin"));
        }

        // Reopen and verify everything persists.
        try (GocryptFs fs = GocryptFs.open(cipherDir, "secretpw".toCharArray())) {
            assertArrayEquals(secret, fs.readAll("/docs/hello.txt"));
            assertArrayEquals(big, fs.readAll("/big.bin"));
            assertTrue(fs.list("/").stream().anyMatch(e -> e.plainName().equals("docs")));
        }

        // Wrong password must fail.
        assertThrows(IOException.class, () -> GocryptFs.open(cipherDir, "wrong".toCharArray()));
    }

    @Test
    void openWriteStreaming() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        byte[] data = new byte[250_000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i * 17);
        }

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/stream.bin");
            try (OutputStream out = fs.openWrite("/stream.bin")) {
                for (int off = 0; off < data.length; off += 4096) {
                    int len = Math.min(4096, data.length - off);
                    out.write(data, off, len);
                }
            }
            assertArrayEquals(data, fs.readAll("/stream.bin"));
        }

        // Reopen and verify the streamed content persisted.
        try (GocryptFs fs = GocryptFs.open(cipherDir, "pw".toCharArray())) {
            assertArrayEquals(data, fs.readAll("/stream.bin"));
        }
    }

    @Test
    void openWriteOverwritesExistingContent() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/f.txt");
            fs.write("/f.txt", 0, "old content longer".getBytes(StandardCharsets.UTF_8));

            try (OutputStream out = fs.openWrite("/f.txt")) {
                out.write("new".getBytes(StandardCharsets.UTF_8));
            }

            // openWrite starts at offset 0 and does not truncate, so the tail of
            // the previous content remains (mirrors write(String, offset, data)).
            assertEquals("new content longer",
                    new String(fs.readAll("/f.txt"), StandardCharsets.UTF_8));
        }
    }

    @Test
    void longFileNames() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 40; i++) {
            longName.append("segment").append(i).append('-');
        }
        String name = longName.toString();

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/" + name);
            fs.write("/" + name, 0, "longname content".getBytes(StandardCharsets.UTF_8));

            List<String> names = fs.list("/").stream()
                    .map(DirEntry::plainName).collect(Collectors.toList());
            assertTrue(names.contains(name), "long name should be listed");

            assertEquals("longname content",
                    new String(fs.readAll("/" + name), StandardCharsets.UTF_8));
        }

        try (GocryptFs fs = GocryptFs.open(cipherDir, "pw".toCharArray())) {
            assertEquals("longname content",
                    new String(fs.readAll("/" + name), StandardCharsets.UTF_8));
        }
    }

    @Test
    void sparseWritesAndTruncate() throws IOException {
        Path cipherDir = tmp.resolve("cipher");
        Files.createDirectory(cipherDir);

        try (GocryptFs fs = GocryptFs.create(cipherDir, "pw".toCharArray())) {
            fs.createFile("/hole.bin");

            // Write beyond EOF, creating a hole.
            byte[] tail = "tail".getBytes(StandardCharsets.UTF_8);
            fs.write("/hole.bin", 9000, tail);

            assertEquals(9000 + tail.length, fs.size("/hole.bin"));

            byte[] all = fs.readAll("/hole.bin");
            assertEquals(9000 + tail.length, all.length);
            for (int i = 0; i < 9000; i++) {
                assertEquals(0, all[i], "hole byte at " + i);
            }
            assertEquals("tail", new String(all, 9000, tail.length, StandardCharsets.UTF_8));

            // Truncate down and back up.
            fs.truncate("/hole.bin", 5000);
            assertEquals(5000, fs.size("/hole.bin"));
            fs.truncate("/hole.bin", 20000);
            assertEquals(20000, fs.size("/hole.bin"));
            byte[] grown = fs.readAll("/hole.bin");
            assertEquals(20000, grown.length);
        }
    }

}
