package psi.cache;

import psi.cache.enumeration.PsiCacheOperationType;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class PsiCacheProviderImplementation implements PsiCacheProvider {

    private Map<Long, Map<PsiCacheOperationType, Map<String,String>>> rootMap = new ConcurrentHashMap<>();

    /**
     * Retrieve the output of the operation applied to an input value, using a given key.
     *
     * @param keyId             id identifying the key actually used by the algorithm.
     * @param cacheObjectType   enum identifying the operation corresponding to the result to be retrieved.
     * @param input             input value of the operation which result has to be retrieved.
     *
     * @return an Optional containing the the cached result of the operation if present, Optional.empty() otherwise
     */
    public Optional<String> get(long keyId, PsiCacheOperationType cacheObjectType, String input){
        Map<PsiCacheOperationType, Map<String, String>> keyIdMap = rootMap.get(keyId);
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
    public void put(long keyId, PsiCacheOperationType cacheObjectType, String input, String output){
        Map<PsiCacheOperationType, Map<String, String>> keyIdMap = rootMap.computeIfAbsent(keyId, k -> new ConcurrentHashMap<>());
        Map<String, String> optTypeMap = keyIdMap.computeIfAbsent(cacheObjectType, k -> new ConcurrentHashMap<>());
        optTypeMap.put(input, output);
    }

    public long size (){
        long size = 0;
        for(Long keyId : rootMap.keySet())
            for(PsiCacheOperationType opt : rootMap.get(keyId).keySet())
                size += rootMap.get(keyId).get(opt).size();
        return size;
    }

}
