package psi;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class that verifies the correctness of the PsiCacheProvider implementation used to test the sdk.
 */
class PsiCacheProviderImplementationTest {

    @Test
    void getCachedEncryptedValueTest(){
        PsiCacheProviderImplementation cacheImpl = new PsiCacheProviderImplementation();

        long keyId0 = 0L;
        long keyId1 = 1L;

        String inputValue0 = "inputValue0";
        String inputValue1 = "inputValue1";
        String outputValue1a = "outputValue1a";
        String outputValue1b = "outputValue1b";

        cacheImpl.put(generateKeyString(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION,inputValue1),outputValue1a);
        cacheImpl.put(generateKeyString(keyId1, CacheOperationType.REVERSE_VALUE,inputValue1),outputValue1b);
        assertFalse(cacheImpl.get(generateKeyString(keyId0, CacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1)).isPresent());
        assertFalse(cacheImpl.get(generateKeyString(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue0)).isPresent());
        assertFalse(cacheImpl.get(generateKeyString(keyId1, CacheOperationType.BLIND_SIGNATURE_ENCRYPTION, inputValue1)).isPresent());

        assertTrue(cacheImpl.get(generateKeyString(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1)).isPresent());
        assertEquals(outputValue1a, cacheImpl.get(generateKeyString(keyId1, CacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1)).get());
        assertTrue(cacheImpl.get(generateKeyString(keyId1, CacheOperationType.REVERSE_VALUE, inputValue1)).isPresent());
        assertEquals(outputValue1b, cacheImpl.get(generateKeyString(keyId1, CacheOperationType.REVERSE_VALUE, inputValue1)).get());
    }

    private static String generateKeyString(Long keyId, CacheOperationType cacheObjectType, String input){
        return keyId + cacheObjectType.toString() + input;
    }


}

