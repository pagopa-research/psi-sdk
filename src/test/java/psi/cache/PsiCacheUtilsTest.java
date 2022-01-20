package psi.cache;

import org.junit.jupiter.api.Test;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.RandomEncryptedCacheObject;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerKeyDescriptionFactory;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

// This class is used to test the EncryptionCacheProviderImplementation used to perform other tests
public class PsiCacheUtilsTest {

    @Test
    public void verifyCacheKeyIdCorrectnessTest(){
        PsiCacheProviderImplementation cacheImpl = new PsiCacheProviderImplementation();

        PsiServerKeyDescription bsKeyDescription1 = PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                "privateKey1",
                "publicKey1",
                "modulus1");

        PsiServerKeyDescription bsKeyDescription2 = PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                "privateKey2",
                "publicKey2",
                "modulus2");

        Long keyId1 = PsiCacheUtils.getKeyId(bsKeyDescription1, cacheImpl);
        assertEquals(keyId1, PsiCacheUtils.getKeyId(bsKeyDescription1, cacheImpl));

        Long keyId2 = PsiCacheUtils.getKeyId(bsKeyDescription2, cacheImpl);
        assertEquals(keyId2, PsiCacheUtils.getKeyId(bsKeyDescription2, cacheImpl));

        assertNotEquals(keyId1, keyId2);
    }


    @Test
    public void putGetCachedObjectTest(){
        PsiCacheProviderImplementation cacheImpl = new PsiCacheProviderImplementation();

        PsiServerKeyDescription bsKeyDescription1 = PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                "privateKey1",
                "publicKey1",
                "modulus1");

        PsiServerKeyDescription bsKeyDescription2 = PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                "privateKey2",
                "publicKey2",
                "modulus2");

        Long keyId1 = PsiCacheUtils.getKeyId(bsKeyDescription1, cacheImpl);
        Long keyId2 = PsiCacheUtils.getKeyId(bsKeyDescription2, cacheImpl);


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
                PsiCacheUtils.getCachedObject(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, RandomEncryptedCacheObject.class, new PsiCacheProviderImplementation());
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
    }

}
