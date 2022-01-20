package psi.cache;

import org.junit.jupiter.api.Test;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.utils.CustomTypeConverter;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

// This class is used to test the EncryptionCacheProviderImplementation used to perform other tests
public class PsiCacheProviderImplementationTest {


    @Test
    public void getCachedEncryptedValueTest(){
        PsiCacheProviderImplementation cacheImpl = new PsiCacheProviderImplementation();

        long keyId0 = 0L;
        long keyId1 = 1L;

        String inputValue0 = "inputValue0";
        String inputValue1 = "inputValue1";
        String outputValue1a = "outputValue1a";
        String outputValue1b = "outputValue1b";

        cacheImpl.put(generateKeyString(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION,inputValue1),outputValue1a);
        cacheImpl.put(generateKeyString(keyId1, PsiCacheOperationType.REVERSE_VALUE,inputValue1),outputValue1b);
        assertFalse(cacheImpl.get(generateKeyString(keyId0, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1)).isPresent());
        assertFalse(cacheImpl.get(generateKeyString(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue0)).isPresent());
        assertFalse(cacheImpl.get(generateKeyString(keyId1, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, inputValue1)).isPresent());

        assertTrue(cacheImpl.get(generateKeyString(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1)).isPresent());
        assertEquals(outputValue1a, cacheImpl.get(generateKeyString(keyId1, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, inputValue1)).get());
        assertTrue(cacheImpl.get(generateKeyString(keyId1, PsiCacheOperationType.REVERSE_VALUE, inputValue1)).isPresent());
        assertEquals(outputValue1b, cacheImpl.get(generateKeyString(keyId1, PsiCacheOperationType.REVERSE_VALUE, inputValue1)).get());
    }

    private static String generateKeyString(Long keyId, PsiCacheOperationType cacheObjectType, String input){
        return keyId + cacheObjectType.toString() + input;
    }

}
