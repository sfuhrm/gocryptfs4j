package de.sfuhrm.gocryptfs4j.store;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.WeakHashMap;

/**
 * Resolves a {@link URI} to a {@link CipherStore} by dispatching on its scheme
 * to a registered {@link CipherStoreProvider}.
 *
 * <p>Providers are discovered through {@link ServiceLoader}; see
 * {@link CipherStoreProvider} for how to register one.</p>
 */
public final class CipherStores {

    /**
     * Discovered providers, cached per {@link ClassLoader}. The thread context
     * class loader can differ between calls in application servers or plugin
     * environments, so providers are looked up lazily and remembered per class
     * loader instead of once in a static initializer. A {@link WeakHashMap}
     * keeps a redeployed class loader (and its providers) collectable.
     */
    private static final Map<ClassLoader, List<CipherStoreProvider>> PROVIDERS =
            Collections.synchronizedMap(new WeakHashMap<>());

    /** Prevents instantiation. */
    private CipherStores() {
    }

    /**
     * Opens the {@link CipherStore} identified by {@code uri} using the
     * {@link CipherStoreProvider} registered for its scheme. Providers are
     * discovered through the current thread's context class loader.
     *
     * @param uri the URI identifying the store, for example {@code memory:///}
     *            or {@code s3://bucket/prefix}
     * @param env backend-specific options, or {@code null} for defaults
     * @return the store
     * @throws IOException if no provider handles the scheme, or the store cannot
     *                     be created
     * @throws NullPointerException if {@code uri} is {@code null}
     */
    public static CipherStore newStore(URI uri, Map<String, ?> env) throws IOException {
        ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
        ClassLoader classLoader = contextClassLoader != null
                ? contextClassLoader
                : ClassLoader.getSystemClassLoader();
        return newStore(uri, env, classLoader);
    }

    /**
     * Opens the {@link CipherStore} identified by {@code uri} using the
     * {@link CipherStoreProvider} registered for its scheme. Providers are
     * discovered through the given class loader, which is useful in plugin
     * environments where a provider ships outside the application's class path.
     *
     * @param uri         the URI identifying the store, for example {@code memory:///}
     *                    or {@code s3://bucket/prefix}
     * @param env         backend-specific options, or {@code null} for defaults
     * @param classLoader the class loader to discover providers with
     * @return the store
     * @throws IOException if no provider handles the scheme, or the store cannot
     *                     be created
     * @throws NullPointerException if {@code uri} or {@code classLoader} is
     *                              {@code null}
     */
    public static CipherStore newStore(URI uri, Map<String, ?> env, ClassLoader classLoader)
            throws IOException {
        Objects.requireNonNull(uri, "uri");
        Objects.requireNonNull(classLoader, "classLoader");
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("URI has no scheme: " + uri);
        }
        for (CipherStoreProvider provider : providersFor(classLoader)) {
            if (provider.scheme().equalsIgnoreCase(scheme)) {
                return provider.newStore(uri, env);
            }
        }
        throw new IOException("no CipherStoreProvider for scheme '" + scheme + "'");
    }

    /**
     * Returns the providers discovered for {@code classLoader}, loading and
     * caching them on first use.
     *
     * @param classLoader the class loader to discover providers with
     * @return the discovered providers
     */
    private static List<CipherStoreProvider> providersFor(ClassLoader classLoader) {
        synchronized (PROVIDERS) {
            List<CipherStoreProvider> providers = PROVIDERS.get(classLoader);
            if (providers == null) {
                providers = loadProviders(classLoader);
                PROVIDERS.put(classLoader, providers);
            }
            return providers;
        }
    }

    /**
     * Discovers all {@link CipherStoreProvider} implementations registered via
     * {@link ServiceLoader}. A malformed provider configuration raises a
     * {@link ServiceConfigurationError}, which is translated into a
     * {@link RuntimeException} here so that the failure is not cached and a
     * later call can retry after the class path has been fixed.
     *
     * @param classLoader the class loader to discover providers with
     * @return the discovered providers
     */
    private static List<CipherStoreProvider> loadProviders(ClassLoader classLoader) {
        List<CipherStoreProvider> providers = new ArrayList<>();
        try {
            for (CipherStoreProvider provider :
                    ServiceLoader.load(CipherStoreProvider.class, classLoader)) {
                providers.add(provider);
            }
        } catch (ServiceConfigurationError e) {
            throw new IllegalStateException(
                    "failed to load CipherStoreProvider implementations", e);
        }
        return Collections.unmodifiableList(providers);
    }
}
