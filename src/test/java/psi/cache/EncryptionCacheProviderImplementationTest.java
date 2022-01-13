package psi.cache;

import org.junit.jupiter.api.Test;
import psi.cache.enumeration.CacheOperationType;

import static org.junit.jupiter.api.Assertions.*;

// This class is used to test the EncryptionCacheProviderImplementation used to perform other tests
public class EncryptionCacheProviderImplementationTest{

    EncryptionCacheProviderImplementation cacheImpl = new EncryptionCacheProviderImplementation();

    @Test
    public void getCachedEncryptedValueTest(){
        long keyId0 = 0L;
        long keyId1 = 1L;

        String inputValue0 = "inputValue0";
        String inputValue1 = "inputValue1";
        String outputValue1a = "outputValue1a";
        String outputValue1b = "outputValue1b";

        cacheImpl.putEncryptedValue(keyId1,CacheOperationType.PRIVATE_KEY_ENCRYPTION,inputValue1,outputValue1a);
        cacheImpl.putEncryptedValue(keyId1,CacheOperationType.REVERSE_VALUE,inputValue1,outputValue1b);
        assertFalse(cacheImpl.getCachedEncryptedValue(keyId0, CacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1).isPresent());
        assertFalse(cacheImpl.getCachedEncryptedValue(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue0).isPresent());
        assertFalse(cacheImpl.getCachedEncryptedValue(keyId1, CacheOperationType.BLIND_SIGNATURE_ENCRYPTION, inputValue1).isPresent());

        assertTrue(cacheImpl.getCachedEncryptedValue(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1).isPresent());
        assertEquals(outputValue1a, cacheImpl.getCachedEncryptedValue(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1).get());
        assertTrue(cacheImpl.getCachedEncryptedValue(keyId1, CacheOperationType.REVERSE_VALUE, inputValue1).isPresent());
        assertEquals(outputValue1b, cacheImpl.getCachedEncryptedValue(keyId1, CacheOperationType.REVERSE_VALUE, inputValue1).get());
    }

}
