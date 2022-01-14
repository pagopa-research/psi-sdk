package psi.cache;

import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.PsiCacheObject;
import psi.exception.CustomRuntimeException;
import psi.exception.MissingCacheKeyIdException;
import psi.model.KeyDescription;
import psi.utils.Base64EncoderHelper;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

public class PsiCacheUtils {

    private static final String CACHE_VALIDATION_KEY_INPUT = "CANARY";

    private PsiCacheUtils() {}

    /**
     * Verifies that the keyId associated to the pair <key,modulus> is correct respect tha cache content and implementation
     *
     * @param cacheKeyId        id identifying the key actually used by the algorithm.
     * @param keyDescription               key (public or private) used by the encryption function and associated to the cacheKeyId.
     * @param encryptionCacheProvider   encryption cache implementation.
     *
     * @return false if the check value is present in the cache for the specified cacheKeyId and it is different respect the one expected, true otherwise
     */
    public static boolean verifyCacheKeyIdCorrectness(Long cacheKeyId, KeyDescription keyDescription, PsiCacheProvider encryptionCacheProvider) {
        if(cacheKeyId == null)
            throw new MissingCacheKeyIdException();
        String base64KeyDescription = Base64EncoderHelper.objectToBase64(keyDescription);
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            String hashedBase64 = new String(messageDigest.digest(base64KeyDescription.getBytes()));
            Optional<String> cachedValue =
                    encryptionCacheProvider.get(cacheKeyId, PsiCacheOperationType.KEY_VALIDATION, CACHE_VALIDATION_KEY_INPUT);
            if(!cachedValue.isPresent()){
                encryptionCacheProvider.put(cacheKeyId, PsiCacheOperationType.KEY_VALIDATION, CACHE_VALIDATION_KEY_INPUT, hashedBase64);
                return true;
            }
            return cachedValue.get().equals(hashedBase64);
        } catch (NoSuchAlgorithmException e) {
            throw new CustomRuntimeException("SHA-256 not supported");
        }
    }

    public static <T> Optional<T> getCachedObject(Long keyId, PsiCacheOperationType cacheObjectType, BigInteger input, Class<T> typeParameterClass, PsiCacheProvider encryptionCacheProvider){
        String inputString = CustomTypeConverter.convertBigIntegerToString(input);
        Optional<String> cachedValueBase64 = encryptionCacheProvider.get(keyId, cacheObjectType, inputString);
        if(!cachedValueBase64.isPresent())
            return Optional.empty();
        T cachedObject = Base64EncoderHelper.base64ToObject(cachedValueBase64.get(), typeParameterClass);
        return Optional.of(cachedObject);
    }

    public static void putCachedObject(Long keyId, PsiCacheOperationType cacheObjectType, BigInteger input, PsiCacheObject output, PsiCacheProvider encryptionCacheProvider){
        String inputString = CustomTypeConverter.convertBigIntegerToString(input);
        String outputString = Base64EncoderHelper.objectToBase64(output);
        encryptionCacheProvider.put(keyId,cacheObjectType,inputString,outputString);
    }
}
