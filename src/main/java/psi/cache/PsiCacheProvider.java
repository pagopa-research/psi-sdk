package psi.cache;

import java.util.Optional;

public interface PsiCacheProvider {

    /**
     * Retrieves the value to which the specified key is mapped.
     *
     * @param key the key whose associated value is to be returned
     *
     * @return an Optional containing the cached value to which the specified key is mapped,
     *          or Optional.empty() otherwise if the cache contains no mapping for the key
     */
    public Optional<String> get(String key);

    /**
     * If the specified key is not present into the cache, stores it linked to the input value.
     *
     * @param key key with which the specified value is to be associated
     * @param value alue to be associated with the specified key
     */
    public void put(String key, String value);
}
