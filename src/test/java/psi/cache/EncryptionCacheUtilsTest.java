package psi.cache;

import org.junit.jupiter.api.Test;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.RandomEncryptedCacheObject;
import psi.server.algorithm.bs.model.BsPsiServerKeyDescription;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

// This class is used to test the EncryptionCacheProviderImplementation used to perform other tests
public class EncryptionCacheUtilsTest {


    @Test
    public void verifyCacheKeyIdCorrectnessTest(){
        EncryptionCacheProviderImplementation cacheImpl = new EncryptionCacheProviderImplementation();

        long keyId1 = 1L;
        long keyId2 = 2L;

        BsPsiServerKeyDescription bsKeyDescription1 = new BsPsiServerKeyDescription();
        bsKeyDescription1.setKeyId(keyId1);
        bsKeyDescription1.setPrivateKey("privateKey1");
        bsKeyDescription1.setPublicKey("publicKey1");
        bsKeyDescription1.setModulus("modulus1");
        BsPsiServerKeyDescription bsKeyDescription2 = new BsPsiServerKeyDescription();
        bsKeyDescription2.setKeyId(keyId2);
        bsKeyDescription2.setPrivateKey("privateKey2");
        bsKeyDescription2.setPublicKey("publicKey2");
        bsKeyDescription2.setModulus("modulus2");

        assertTrue(PsiCacheUtils.verifyCacheKeyIdCorrectness(keyId1, bsKeyDescription1, cacheImpl));
        assertTrue(PsiCacheUtils.verifyCacheKeyIdCorrectness(keyId2, bsKeyDescription2, cacheImpl));

        assertTrue(PsiCacheUtils.verifyCacheKeyIdCorrectness(keyId1, bsKeyDescription1, cacheImpl));
        assertTrue(PsiCacheUtils.verifyCacheKeyIdCorrectness(keyId2, bsKeyDescription2, cacheImpl));

        assertFalse(PsiCacheUtils.verifyCacheKeyIdCorrectness(keyId1, bsKeyDescription2, cacheImpl));
        assertFalse(PsiCacheUtils.verifyCacheKeyIdCorrectness(keyId2, bsKeyDescription1, cacheImpl));
    }


    @Test
    public void putGetCachedObjectTest(){
        EncryptionCacheProviderImplementation cacheImpl = new EncryptionCacheProviderImplementation();

        long keyId1 = 1L;
        long keyId2 = 2L;

        BsPsiServerKeyDescription bsKeyDescription1 = new BsPsiServerKeyDescription();
        bsKeyDescription1.setKeyId(keyId1);
        bsKeyDescription1.setPrivateKey("privateKey1");
        bsKeyDescription1.setPublicKey("publicKey1");
        bsKeyDescription1.setModulus("modulus1");
        BsPsiServerKeyDescription bsKeyDescription2 = new BsPsiServerKeyDescription();
        bsKeyDescription2.setKeyId(keyId2);
        bsKeyDescription2.setPrivateKey("privateKey2");
        bsKeyDescription2.setPublicKey("publicKey2");
        bsKeyDescription2.setModulus("modulus2");

        PsiCacheUtils.verifyCacheKeyIdCorrectness(keyId1, bsKeyDescription1, cacheImpl);
        PsiCacheUtils.verifyCacheKeyIdCorrectness(keyId2, bsKeyDescription2, cacheImpl);


        BigInteger emptyValue = CustomTypeConverter.convertStringToBigInteger("empty");
        BigInteger clearValue = CustomTypeConverter.convertStringToBigInteger("clear value");
        BigInteger randomValue = CustomTypeConverter.convertStringToBigInteger("Random value");
        BigInteger encryptedValue = CustomTypeConverter.convertStringToBigInteger("Encrypted value");
        RandomEncryptedCacheObject randomEncryptedCacheObject = new RandomEncryptedCacheObject(randomValue,encryptedValue);

        PsiCacheUtils.putCachedObject(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, randomEncryptedCacheObject, cacheImpl);
        Optional<RandomEncryptedCacheObject> randomEncryptedCacheObjectCached =
                PsiCacheUtils.getCachedObject(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, RandomEncryptedCacheObject.class, cacheImpl);
        assertTrue(randomEncryptedCacheObjectCached.isPresent());
        assertEquals(randomEncryptedCacheObject, randomEncryptedCacheObjectCached.get());

        randomEncryptedCacheObjectCached =
                PsiCacheUtils.getCachedObject(keyId2, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, RandomEncryptedCacheObject.class, cacheImpl);
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
        randomEncryptedCacheObjectCached =
                PsiCacheUtils.getCachedObject(keyId1, PsiCacheOperationType.KEY_VALIDATION, clearValue, RandomEncryptedCacheObject.class, cacheImpl);
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
        randomEncryptedCacheObjectCached =
                PsiCacheUtils.getCachedObject(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, emptyValue, RandomEncryptedCacheObject.class, cacheImpl);
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
        randomEncryptedCacheObjectCached =
                PsiCacheUtils.getCachedObject(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, RandomEncryptedCacheObject.class, new EncryptionCacheProviderImplementation());
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
    }

}
