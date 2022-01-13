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

    public <T> Optional<T> getCachedObject(Long keyId, CacheOperationType cacheObjectType, BigInteger input, Class<T> typeParameterClass){
        String inputString = CustomTypeConverter.convertBigIntegerToString(input);
        Optional<String> cachedValueBase64 =  this.getCachedEncryptedValue(keyId, cacheObjectType, inputString);
        if(!cachedValueBase64.isPresent())
            return Optional.empty();
        T cachedObject = Base64EncoderHelper.base64ToDto(cachedValueBase64.get(), typeParameterClass);
        return Optional.of(cachedObject);
    }

    public void putCachedObject(Long keyId, CacheOperationType cacheObjectType, BigInteger input, CacheObject output){
        //TODO: non sono sicuro che non specificare il tipo qui funzioni, verificare
        String inputString = CustomTypeConverter.convertBigIntegerToString(input);
        String outputString = Base64EncoderHelper.dtoToBase64(output);
        this.putEncryptedValue(keyId,cacheObjectType,inputString,outputString);
    }
}
