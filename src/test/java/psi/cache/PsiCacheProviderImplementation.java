package psi.cache;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class PsiCacheProviderImplementation implements PsiCacheProvider {

    private Map<String, String> cache = new ConcurrentHashMap<>();

    /**
     * Retrieve the value linked to a given key.
     *
     * @param key   key corresponding to the value to be retrieved
     *
     * @return an Optional containing the the cached value if present, Optional.empty() otherwise
     */
    public Optional<String> get(String key){
        String output = cache.get(key);
        if (output == null)
            return Optional.empty();
        else
            return Optional.of(output);
    }

    /**
     * Stores the pair <key, value> into the cache. If the key exists, it is not replaced
     *
     * @param key       key corresponding to the value to be stored.
     * @param value     value to be stored.
     */
    public void put(String key, String value){
        cache.putIfAbsent(key, value);
    }

    public long size (){
        return cache.size();
    }

}
