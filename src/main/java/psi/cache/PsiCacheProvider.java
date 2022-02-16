package psi.cache;

import java.util.Optional;

/**
 * An interface representing a key-value cache used by the sdk to store the results of heavyweight mathematical
 * operations (such as encryption operations), which can be read in subsequent executions with the same inputs
 * to speed up the execution.
 * Since the goal of the cache is to reduce the computational time with respect to running the actual computations,
 * reading and writing to the cache should be relatively lightweight.
 * When the cache is enabled, the sdk performs concurrent calls to the caching layer.
 * Consequently, the implementations of this interface should be thread safe.
 */
public interface PsiCacheProvider {

    /**
     * Gets the value associated to the input key.
     *
     * @param key the key whose associated value is returned
     * @return an Optional containing the cached value to which the specified key is mapped,
     * or Optional.empty() if the cache contains no mapping for the key
     */
    Optional<String> get(String key);

    /**
     * If the specified key is not present in the cache, stores it with the passed value. If it
     * is already present, do nothing.
     *
     * @param key   key of the cache entry
     * @param value value of the cache entry associated to the key
     */
    void put(String key, String value);
}
