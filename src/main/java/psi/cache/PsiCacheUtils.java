package psi.cache;

import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.PsiCacheObject;
import psi.exception.CustomRuntimeException;
import psi.exception.MissingCacheKeyIdException;
import psi.model.PsiKeyDescription;
import psi.utils.Base64EncoderHelper;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Optional;

public class PsiCacheUtils {

    private PsiCacheUtils() {}

    /**
     * Retrieves the keyId corresponding to the keyDescription is present, otherwise a new keyId is generated and stored.
     *
     * @param keyDescription key (public or private) used by the encryption function.
     * @param encryptionCacheProvider encryption cache implementation.
     *
     * @return the keyId corresponding to the keyDescription
     */
    public static Long getKeyId(PsiKeyDescription keyDescription, PsiCacheProvider encryptionCacheProvider) {
        String base64KeyDescription = Base64EncoderHelper.objectToBase64(keyDescription);
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

    private static String generateKeyString(Long keyId, PsiCacheOperationType cacheObjectType, BigInteger input){
        return keyId + cacheObjectType.toString() + CustomTypeConverter.convertBigIntegerToString(input);
    }

    public static <T> Optional<T> getCachedObject(Long keyId, PsiCacheOperationType cacheObjectType, BigInteger input, Class<T> typeParameterClass, PsiCacheProvider psiCacheProvider){
        String key = generateKeyString(keyId, cacheObjectType, input);
        Optional<String> cachedValueBase64 = psiCacheProvider.get(key);
        if(!cachedValueBase64.isPresent())
            return Optional.empty();
        T cachedObject = Base64EncoderHelper.base64ToObject(cachedValueBase64.get(), typeParameterClass);
        return Optional.of(cachedObject);
    }

    public static void putCachedObject(Long keyId, PsiCacheOperationType cacheObjectType, BigInteger input, PsiCacheObject output, PsiCacheProvider psiCacheProvider){
        String key = generateKeyString(keyId, cacheObjectType, input);
        String value = Base64EncoderHelper.objectToBase64(output);
        psiCacheProvider.put(key, value);
    }
}
