package psi.cache;

import java.util.Optional;

/**
 * An interface representing a key-value cache used by the sdk to store the results of heavyweight mathematical
 * operations, in order to use these results when requested again with the same inputs (e.g. operation type, keys).
 * Since the cache is used to reduce the computational time required, the provided service must guarantee fast responses.
 * Since the cache must serve concurrently by multiple requests, its implementations has to be thread safe.
 */
public interface PsiCacheProvider {

    /**
     * Retrieves the value to which the specified key is mapped.
     * @param key the key whose associated value is to be returned
     * @return an Optional containing the cached value to which the specified key is mapped,
     *          or Optional.empty() if the cache contains no mapping for the key
     */
    public Optional<String> get(String key);

    /**
     * If the specified key is not contained into the cache, stores it with the specified input value,
     * otherwise the state of the cache does not change.
     * @param key   key with which the specified value is to be associated
     * @param value value to be associated with the specified key
     */
    public void put(String key, String value);
}
