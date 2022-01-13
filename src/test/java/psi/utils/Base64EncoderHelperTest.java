package psi.utils;

import org.junit.jupiter.api.Test;
import psi.cache.model.RandomEncryptedCacheObject;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Base64EncoderHelperTest {

    @Test
    public void encodeDecodeTest(){
        // Testing on simple Object, as a String
        String clearString = "Simple value";
        String clearStringToBase64 = Base64EncoderHelper.dtoToBase64(clearString);
        assertEquals(clearString, Base64EncoderHelper.base64ToDto(clearStringToBase64, String.class));

        // Testing on BigInteger
        BigInteger clearBigInteger = CustomTypeConverter.convertStringToBigInteger("BigInteger value");
        String clearBigIntegerToBase64 = Base64EncoderHelper.dtoToBase64(clearBigInteger);
        assertEquals(clearBigInteger, Base64EncoderHelper.base64ToDto(clearBigIntegerToBase64, BigInteger.class));

        // Testing con complex object
        BigInteger randomValue = CustomTypeConverter.convertStringToBigInteger("Random value");
        BigInteger encryptedValue = CustomTypeConverter.convertStringToBigInteger("Encrypted value");
        RandomEncryptedCacheObject clearObject = new RandomEncryptedCacheObject(randomValue,encryptedValue);
        String clearObjectToBase64 = Base64EncoderHelper.dtoToBase64(clearObject);
        assertEquals(clearObject, Base64EncoderHelper.base64ToDto(clearObjectToBase64, RandomEncryptedCacheObject.class));
    }

}
