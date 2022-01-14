package psi.cache;

import org.junit.jupiter.api.Test;
import psi.cache.enumeration.PsiCacheOperationType;

import static org.junit.jupiter.api.Assertions.*;

// This class is used to test the EncryptionCacheProviderImplementation used to perform other tests
public class EncryptionCacheProviderImplementationTest{


    @Test
    public void getCachedEncryptedValueTest(){
        EncryptionCacheProviderImplementation cacheImpl = new EncryptionCacheProviderImplementation();

        long keyId0 = 0L;
        long keyId1 = 1L;

        String inputValue0 = "inputValue0";
        String inputValue1 = "inputValue1";
        String outputValue1a = "outputValue1a";
        String outputValue1b = "outputValue1b";

        cacheImpl.put(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION,inputValue1,outputValue1a);
        cacheImpl.put(keyId1, PsiCacheOperationType.REVERSE_VALUE,inputValue1,outputValue1b);
        assertFalse(cacheImpl.get(keyId0, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1).isPresent());
        assertFalse(cacheImpl.get(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue0).isPresent());
        assertFalse(cacheImpl.get(keyId1, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, inputValue1).isPresent());

        assertTrue(cacheImpl.get(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1).isPresent());
        assertEquals(outputValue1a, cacheImpl.get(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1).get());
        assertTrue(cacheImpl.get(keyId1, PsiCacheOperationType.REVERSE_VALUE, inputValue1).isPresent());
        assertEquals(outputValue1b, cacheImpl.get(keyId1, PsiCacheOperationType.REVERSE_VALUE, inputValue1).get());
    }

}
