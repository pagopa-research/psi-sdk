package psi;

import psi.cache.PsiCacheProvider;
import psi.exception.CustomRuntimeException;
import psi.model.PsiKeyDescription;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;

class CacheUtils {

    private CacheUtils() {}

    /**
     * Retrieves the keyId corresponding to the keyDescription is present, otherwise a new keyId is generated and stored.
     *
     * @param keyDescription key (public or private) used by the encryption function.
     * @param encryptionCacheProvider encryption cache implementation.
     *
     * @return the keyId corresponding to the keyDescription
     */
    static Long getKeyId(PsiKeyDescription keyDescription, PsiCacheProvider encryptionCacheProvider) {
        String base64KeyDescription = CustomTypeConverter.convertObjectToString(keyDescription);
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            String keyDescriptionDigest = new String(messageDigest.digest(base64KeyDescription.getBytes()));
            Optional<String> cachedValue =
                    encryptionCacheProvider.get(keyDescriptionDigest);
            if(!cachedValue.isPresent()){
                Long keyId = (new SecureRandom()).nextLong();
                encryptionCacheProvider.put(keyDescriptionDigest, keyId.toString());
                return keyId;
            }
            return Long.parseLong(cachedValue.get());
        } catch (NoSuchAlgorithmException e) {
            throw new CustomRuntimeException("SHA-256 not supported");
        }
    }

    private static String generateKeyString(Long keyId, CacheOperationType cacheObjectType, BigInteger input){
        return keyId + cacheObjectType.toString() + CustomTypeConverter.convertBigIntegerToString(input);
    }

    static <T> Optional<T> getCachedObject(Long keyId, CacheOperationType cacheObjectType, BigInteger input, Class<T> typeParameterClass, PsiCacheProvider psiCacheProvider){
        String key = generateKeyString(keyId, cacheObjectType, input);
        Optional<String> cachedValueBase64 = psiCacheProvider.get(key);
        if(!cachedValueBase64.isPresent())
            return Optional.empty();
        T cachedObject = CustomTypeConverter.convertStringToObject(cachedValueBase64.get(), typeParameterClass);
        return Optional.of(cachedObject);
    }

    static void putCachedObject(Long keyId, CacheOperationType cacheObjectType, BigInteger input, CacheObject output, PsiCacheProvider psiCacheProvider){
        String key = generateKeyString(keyId, cacheObjectType, input);
        String value = CustomTypeConverter.convertObjectToString(output);
        psiCacheProvider.put(key, value);
    }
}