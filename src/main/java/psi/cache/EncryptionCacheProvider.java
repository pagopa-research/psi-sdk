package psi.cache;

import psi.cache.enumeration.CacheOperationType;
import psi.cache.model.CacheObject;
import psi.utils.Base64EncoderHelper;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;
import java.util.Optional;

public abstract class EncryptionCacheProvider {

    /**
     * Retrieve the output of the operation applied to an input value, using a given key.
     *
     * @param keyId             id identifying the key actually used by the algorithm.
     * @param cacheObjectType   enum identifying the operation corresponding to the result to be retrieved.
     * @param input             input value of the operation which result has to be retrieved.
     *
     * @return an Optional containing the the cached result of the operation if present, Optional.empty() otherwise
     */
    public abstract Optional<String> getCachedEncryptedValue(long keyId, CacheOperationType cacheObjectType, String input);

    /**
     * Stores the result of the operation applied to an input value, using a given key.
     *
     * @param keyId             id identifying the key actually used by the algorithm.
     * @param cacheObjectType   enum identifying the operation corresponding to the result to be stored.
     * @param input             input value of the operation which result has to be stored.
     * @param output            resulting value of the operation applied to the input value.
     */
    public abstract void putEncryptedValue(long keyId, CacheOperationType cacheObjectType, String input, String output);
}
