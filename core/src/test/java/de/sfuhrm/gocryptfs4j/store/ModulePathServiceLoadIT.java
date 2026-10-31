package de.sfuhrm.gocryptfs4j.store;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Loads the packaged multi-release JAR on the module path and verifies the
 * {@code uses}/{@code provides} wiring in {@code module-info.java}. Without it,
 * {@link CipherStores} could not discover the built-in providers from a named
 * module, because the classpath {@code META-INF/services} fallback is ignored
 * on the module path.
 *
 * <p>This is a failsafe (integration) test: it needs the packaged JAR with its
 * {@code module-info.class}, which only exists after {@code mvn package}.</p>
 */
class ModulePathServiceLoadIT {

    private static final String CORE_MODULE = "de.sfuhrm.gocryptfs4j.core";

    private static final String MAIN_SOURCE =
            "import de.sfuhrm.gocryptfs4j.store.CipherStore;\n"
            + "import de.sfuhrm.gocryptfs4j.store.CipherStores;\n"
            + "import java.net.URI;\n"
            + "public class Main {\n"
            + "    public static void main(String[] args) throws Exception {\n"
            + "        CipherStore memory = CipherStores.newStore(URI.create(\"memory:///\"), null);\n"
            + "        CipherStore file = CipherStores.newStore(URI.create(\"file:///tmp\"), null);\n"
            + "        System.out.println(memory.getClass().getName());\n"
            + "        System.out.println(file.getClass().getName());\n"
            + "    }\n"
            + "}\n";

    @Test
    void resolvesBuiltInProvidersOnModulePath(@TempDir Path dir) throws Exception {
        Path main = dir.resolve("Main.java");
        Files.write(main, MAIN_SOURCE.getBytes(StandardCharsets.UTF_8));

        List<Path> modulePath = new ArrayList<>();
        modulePath.add(coreJar());
        modulePath.add(dependencyJar("bcprov-jdk18on"));
        modulePath.add(dependencyJar("gson"));
        modulePath.add(dependencyJar("jspecify"));

        Process process = new ProcessBuilder(
                javaBinary(),
                "--module-path", join(modulePath),
                "--add-modules", CORE_MODULE,
                main.toString())
                .redirectErrorStream(true)
                .start();

        String output = readAll(process.getInputStream());
        assertTrue(process.waitFor(60, TimeUnit.SECONDS), "module-path run timed out: " + output);
        assertEquals(0, process.exitValue(), "module-path run failed: " + output);
        assertTrue(output.contains("de.sfuhrm.gocryptfs4j.store.memory.MapCipherStore"), output);
        assertTrue(output.contains("de.sfuhrm.gocryptfs4j.store.local.PathCipherStore"), output);
    }

    private static String javaBinary() {
        return Paths.get(System.getProperty("java.home"), "bin",
                isWindows() ? "java.exe" : "java").toString();
    }

    private static boolean isWindows() {
        return File.separatorChar == '\\';
    }

    private static Path coreJar() throws IOException {
        Path jar = Paths.get("target", "gocryptfs4j-core-" + projectVersion() + ".jar");
        if (!Files.isRegularFile(jar)) {
            throw new IOException("core jar not found: " + jar);
        }
        return jar;
    }

    private static String projectVersion() throws IOException {
        try (InputStream in = ModulePathServiceLoadIT.class.getClassLoader()
                .getResourceAsStream("de/sfuhrm/gocryptfs4j/config/version.properties")) {
            if (in == null) {
                throw new IOException("version.properties not found on classpath");
            }
            String prefix = "version=";
            String content = readAll(in).trim();
            if (!content.startsWith(prefix)) {
                throw new IOException("unexpected version.properties content: " + content);
            }
            return content.substring(prefix.length()).trim();
        }
    }

    private static Path dependencyJar(String prefix) throws IOException {
        String classpath = System.getProperty("java.class.path");
        for (String entry : classpath.split(File.pathSeparator)) {
            String name = Paths.get(entry).getFileName().toString();
            if (name.startsWith(prefix) && name.endsWith(".jar")) {
                return Paths.get(entry);
            }
        }
        throw new IOException("dependency jar not found on classpath: " + prefix);
    }

    private static String join(List<Path> paths) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < paths.size(); i++) {
            if (i > 0) {
                sb.append(File.pathSeparatorChar);
            }
            sb.append(paths.get(i));
        }
        return sb.toString();
    }

    private static String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
}
