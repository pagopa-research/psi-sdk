package psi.cache;

import psi.cache.enumeration.CacheOperationType;
import psi.exception.MissingCacheKeyIdException;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;
import java.util.Optional;

public class EncryptionCacheUtils {

    private static final String CACHE_VALIDATION_KEY_INPUT = "CANARY";

    private EncryptionCacheUtils() {}

    /**
     * Verifies that the keyId associated to the pair <key,modulus> is correct respect tha cache content and implementation
     *
     * @param cacheKeyId        id identifying the key actually used by the algorithm.
     * @param key               key (public or private) used by the encryption function and associated to the cacheKeyId.
     * @param modulus           modulus used by the encryption function and associated to the cacheKeyId.
     * @param encryptionCacheProvider   encryption cache implementation.
     *
     * @return false if the check value is present in the cache for the specified cacheKeyId and it is different respect the one expected, true otherwise
     * @throws MissingCacheKeyIdException is the keyId is empty
     */
    public static boolean verifyCacheKeyIdCorrectness(Long cacheKeyId, BigInteger key, BigInteger modulus, EncryptionCacheProvider encryptionCacheProvider) throws MissingCacheKeyIdException {
        if(cacheKeyId == null)
            throw new MissingCacheKeyIdException();
        BigInteger clearValue = CustomTypeConverter.convertStringToBigInteger(CACHE_VALIDATION_KEY_INPUT);
        String encryptedValue = CustomTypeConverter.convertBigIntegerToString(
                clearValue.modPow(key, modulus));
        Optional<String> cachedValue =
                encryptionCacheProvider.getCachedEncryptedValue(cacheKeyId, CacheOperationType.KEY_VALIDATION, CACHE_VALIDATION_KEY_INPUT);
        if(!cachedValue.isPresent()){
            encryptionCacheProvider.putEncryptedValue(cacheKeyId, CacheOperationType.KEY_VALIDATION, CACHE_VALIDATION_KEY_INPUT, encryptedValue);
            return true;
        }
        return cachedValue.get().equals(encryptedValue);
    }
}
