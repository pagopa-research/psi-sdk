package psi;

import psi.cache.PsiCacheProvider;
import psi.exception.CustomRuntimeException;
import psi.model.PsiKeyDescription;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;

/**
 * This class represents a decoupling layer between the external cache implementation and the facilities required
 * by the algorithms, providing a set of methods that hide the translation of objects passed to the cache into
 * cacheable values.
 */
class CacheUtils {

    private CacheUtils() {}

    /**
     * Retrieves the keyId corresponding to the keyDescription if present, otherwise a new keyId is generated and stored.
     * @param keyDescription    object containing the keys used by the encryption function
     * @param psiCacheProvider  cache provider implementation
     * @return the keyId corresponding to the input keyDescription
     */
    static Long getKeyId(PsiKeyDescription keyDescription, PsiCacheProvider psiCacheProvider) {
        String base64KeyDescription = CustomTypeConverter.convertObjectToString(keyDescription);
        try {
            // A digest of the keyDescription is used to link a keyId to the provided keyDescription.
            // In this way the sdk can transparently notice when a keyDescription is reused, exploiting the cache content.
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            String keyDescriptionDigest = new String(messageDigest.digest(base64KeyDescription.getBytes()));
            Optional<String> cachedValue =
                    psiCacheProvider.get(keyDescriptionDigest);
            if(!cachedValue.isPresent()){
                Long keyId = (new SecureRandom()).nextLong();
                psiCacheProvider.put(keyDescriptionDigest, keyId.toString());
                return keyId;
            }
            return Long.parseLong(cachedValue.get());
        } catch (NoSuchAlgorithmException e) {
            throw new CustomRuntimeException("SHA-256 not supported");
        }
    }

    /**
     * Starting from all the input parameters involved into the encrypted value computation, builds a single string that
     * can be used as key of the cache element.
     * @param keyId             id associated to the keyDescription
     * @param cacheObjectType   enum representing an operation type
     * @param input             input value of the encryption operation
     * @return a string that uniquely represents the input parameters
     */
    private static String generateKeyString(Long keyId, CacheOperationType cacheObjectType, BigInteger input){
        return keyId + cacheObjectType.toString() + CustomTypeConverter.convertBigIntegerToString(input);
    }

    /**
     * Retrieves the value mapped to the input parameters (keyId, cacheObjectType, input).
     * @param keyId                 id associated to the keyDescription
     * @param cacheObjectType       enum representing an operation type
     * @param input                 input value of the encryption operation
     * @param typeParameterClass    class type of the object to be retrieved
     * @param psiCacheProvider      cache provider implementation
     * @return an Optional containing the cached value corresponding to the input triple (keyId, cacheObjectType,
     * input), or Optional.empty() if the cache does not contains any value associated to these parameters.
     */
    static <T> Optional<T> getCachedObject(Long keyId, CacheOperationType cacheObjectType, BigInteger input, Class<T> typeParameterClass, PsiCacheProvider psiCacheProvider){
        String key = generateKeyString(keyId, cacheObjectType, input);
        Optional<String> cachedValueBase64 = psiCacheProvider.get(key);
        if(!cachedValueBase64.isPresent())
            return Optional.empty();
        T cachedObject = CustomTypeConverter.convertStringToObject(cachedValueBase64.get(), typeParameterClass);
        return Optional.of(cachedObject);
    }

    /**
     * If the cache does not contains any value associated to the triple (keyId, cacheObjectType, input), stores it with
     * the specified input value, otherwise the state of the cache does not change.
     * @param keyId             id associated to the keyDescription
     * @param cacheObjectType   enum representing an operation type
     * @param input             input value of the encryption operation
     * @param output            output value of the encryption operation
     * @param psiCacheProvider  cache provider implementation
     */
    static void putCachedObject(Long keyId, CacheOperationType cacheObjectType, BigInteger input, CacheObject output, PsiCacheProvider psiCacheProvider){
        String key = generateKeyString(keyId, cacheObjectType, input);
        String value = CustomTypeConverter.convertObjectToString(output);
        psiCacheProvider.put(key, value);
    }
}
