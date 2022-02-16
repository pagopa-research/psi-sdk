package psi;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class that verifies the correctness of the PsiCacheUtils.
 */
class PsiCacheUtilsTest {

    @Test
    void verifyCacheKeyIdCorrectnessTest(){
        PsiCacheProviderImplementation cacheImpl = new PsiCacheProviderImplementation();

        PsiServerKeyDescription bsKeyDescription1 = PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                "privateExponent1",
                "publicExponent1",
                "modulus1");

        PsiServerKeyDescription bsKeyDescription2 = PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                "privateExponent2",
                "publicExponent2",
                "modulus2");

        Long keyId1 = CacheUtils.getKeyId(bsKeyDescription1, cacheImpl);
        assertEquals(keyId1, CacheUtils.getKeyId(bsKeyDescription1, cacheImpl));

        Long keyId2 = CacheUtils.getKeyId(bsKeyDescription2, cacheImpl);
        assertEquals(keyId2, CacheUtils.getKeyId(bsKeyDescription2, cacheImpl));

        assertNotEquals(keyId1, keyId2);
    }


    @Test
    void putGetCachedObjectTest(){
        PsiCacheProviderImplementation cacheImpl = new PsiCacheProviderImplementation();

        PsiServerKeyDescription bsKeyDescription1 = PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                "privateExponent1",
                "publicExponent1",
                "modulus1");

        PsiServerKeyDescription bsKeyDescription2 = PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                "privateExponent2",
                "publicExponent2",
                "modulus2");

        Long keyId1 = CacheUtils.getKeyId(bsKeyDescription1, cacheImpl);
        Long keyId2 = CacheUtils.getKeyId(bsKeyDescription2, cacheImpl);


        BigInteger emptyValue = CustomTypeConverter.convertStringToBigInteger("empty");
        BigInteger clearValue = CustomTypeConverter.convertStringToBigInteger("clear value");
        BigInteger randomValue = CustomTypeConverter.convertStringToBigInteger("Random value");
        BigInteger encryptedValue = CustomTypeConverter.convertStringToBigInteger("Encrypted value");
        CacheObjectRandomEncrypted randomEncryptedCacheObject = new CacheObjectRandomEncrypted(randomValue,encryptedValue);

        CacheUtils.putCachedObject(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, randomEncryptedCacheObject, cacheImpl);
        Optional<CacheObjectRandomEncrypted> randomEncryptedCacheObjectCached =
                CacheUtils.getCachedObject(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, CacheObjectRandomEncrypted.class, cacheImpl);
        assertTrue(randomEncryptedCacheObjectCached.isPresent());
        assertEquals(randomEncryptedCacheObject, randomEncryptedCacheObjectCached.get());

        randomEncryptedCacheObjectCached =
                CacheUtils.getCachedObject(keyId2, CacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, CacheObjectRandomEncrypted.class, cacheImpl);
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
        randomEncryptedCacheObjectCached =
                CacheUtils.getCachedObject(keyId1, CacheOperationType.KEY_VALIDATION, clearValue, CacheObjectRandomEncrypted.class, cacheImpl);
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
        randomEncryptedCacheObjectCached =
                CacheUtils.getCachedObject(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, emptyValue, CacheObjectRandomEncrypted.class, cacheImpl);
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
        randomEncryptedCacheObjectCached =
                CacheUtils.getCachedObject(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, clearValue, CacheObjectRandomEncrypted.class, new PsiCacheProviderImplementation());
        assertFalse(randomEncryptedCacheObjectCached.isPresent());
    }

}
