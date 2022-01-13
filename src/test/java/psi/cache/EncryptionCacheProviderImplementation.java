package psi.cache;

import psi.cache.enumeration.CacheOperationType;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class EncryptionCacheProviderImplementation extends EncryptionCacheProvider{

    Map<Long, Map<CacheOperationType, Map<String,String>>> rootMap = new HashMap<>();;

    /**
     * Retrieve the output of the operation applied to an input value, using a given key.
     *
     * @param keyId             id identifying the key actually used by the algorithm.
     * @param cacheObjectType   enum identifying the operation corresponding to the result to be retrieved.
     * @param input             input value of the operation which result has to be retrieved.
     *
     * @return an Optional containing the the cached result of the operation if present, Optional.empty() otherwise
     */
    public Optional<String> getCachedEncryptedValue(long keyId, CacheOperationType cacheObjectType, String input){
        Map<CacheOperationType, Map<String, String>> keyIdMap = rootMap.get(keyId);
        if (keyIdMap == null)
            return Optional.empty();
        Map<String, String> optTypeMap = keyIdMap.get(cacheObjectType);
        if (optTypeMap == null)
            return Optional.empty();
        String output = optTypeMap.get(input);
        if (output == null)
            return Optional.empty();
        else
            return Optional.of(output);

    }

    /**
     * Stores the result of the operation applied to an input value, using a given key.
     *
     * @param keyId             id identifying the key actually used by the algorithm.
     * @param cacheObjectType   enum identifying the operation corresponding to the result to be stored.
     * @param input             input value of the operation which result has to be stored.
     * @param output            resulting value of the operation applied to the input value.
     */
    public void putEncryptedValue(long keyId, CacheOperationType cacheObjectType, String input, String output){
        Map<CacheOperationType, Map<String, String>> keyIdMap = rootMap.computeIfAbsent(keyId, k -> new HashMap<>());
        Map<String, String> optTypeMap = keyIdMap.computeIfAbsent(cacheObjectType, k -> new HashMap<>());
        optTypeMap.put(input, output);
    }

}
