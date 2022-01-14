package psi.cache;

import psi.cache.enumeration.PsiCacheOperationType;
import java.util.Optional;

public interface PsiCacheProvider {

    /**
     * Retrieve the output of the operation applied to an input value, using a given key.
     *
     * @param keyId             id identifying the key actually used by the algorithm.
     * @param cacheObjectType   enum identifying the operation corresponding to the result to be retrieved.
     * @param input             input value of the operation which result has to be retrieved.
     *
     * @return an Optional containing the the cached result of the operation if present, Optional.empty() otherwise
     */
    public abstract Optional<String> get(long keyId, PsiCacheOperationType cacheObjectType, String input);

    /**
     * Stores the result of the operation applied to an input value, using a given key.
     *
     * @param keyId             id identifying the key actually used by the algorithm.
     * @param cacheObjectType   enum identifying the operation corresponding to the result to be stored.
     * @param input             input value of the operation which result has to be stored.
     * @param output            resulting value of the operation applied to the input value.
     */
    public abstract void put(long keyId, PsiCacheOperationType cacheObjectType, String input, String output);
}
