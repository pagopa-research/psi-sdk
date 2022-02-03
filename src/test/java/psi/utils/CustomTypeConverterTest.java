package psi.utils;

import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import psi.cache.model.RandomEncryptedCacheObject;
import psi.model.EllipticCurve;
import psi.model.PsiAlgorithm;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CustomTypeConverterTest {

    private boolean isStringToBigIntegerConversionBidirectional(String s){
        BigInteger stringToBigInteger = CustomTypeConverter.convertStringToBigInteger(s);
        String bigIntegerToString = CustomTypeConverter.convertBigIntegerToString(stringToBigInteger);
        return s.equals(bigIntegerToString);
    }

    private boolean isBigIntegerToStringConversionBidirectional(BigInteger bigInteger){
        String bigIntegerToString = CustomTypeConverter.convertBigIntegerToString(bigInteger);
        BigInteger stringToBigInteger = CustomTypeConverter.convertStringToBigInteger(bigIntegerToString);
        return bigInteger.equals(stringToBigInteger);
    }

    @Test
    public void stringConversionTest(){
        String s1 = "BasicString1";
        String s2 = "40232931320130013020";
        String s3 = "Rather complex string!*$%";
        String s4 = "String with multiple lines\ncan be tricky\n";
        StringBuilder stringBuilder = new StringBuilder();
        for(int i = 0; i< 100000; i++){
            stringBuilder.append("SuperLongString!");
        }
        String s5 = stringBuilder.toString();

        assertTrue(isStringToBigIntegerConversionBidirectional(s1));
        assertTrue(isStringToBigIntegerConversionBidirectional(s2));
        assertTrue(isStringToBigIntegerConversionBidirectional(s3));
        assertTrue(isStringToBigIntegerConversionBidirectional(s4));
        assertTrue(isStringToBigIntegerConversionBidirectional(s5));
    }

    @Test
    public void bigIntegerConversionTest(){
        BigInteger b1 = new BigInteger("1");
        BigInteger b2 = new BigInteger("21031303028131008");
        BigInteger b3 = new BigInteger("54350935843050380590350803");
        BigInteger b4 = new BigInteger("234");

        StringBuilder stringBuilder = new StringBuilder();
        for(int i = 0; i< 100000; i++){
            stringBuilder.append("8888");
        }
        BigInteger b5 = new BigInteger(stringBuilder.toString());

        assertTrue(isBigIntegerToStringConversionBidirectional(b1));
        assertTrue(isBigIntegerToStringConversionBidirectional(b2));
        assertTrue(isBigIntegerToStringConversionBidirectional(b3));
        assertTrue(isBigIntegerToStringConversionBidirectional(b4));
        assertTrue(isBigIntegerToStringConversionBidirectional(b5));
    }

    @Test
    public void ecPointConversionTest(){

        AsymmetricKeyFactory.AsymmetricEcKey asymmetricEcKey = AsymmetricKeyFactory.generateEcKey(PsiAlgorithm.ECBS, 512);
        EllipticCurve ellipticCurve = new EllipticCurve(asymmetricEcKey.ecSpec);

        ECPoint ecPoint = EllipticCurve.multiply(ellipticCurve.mapMessage(BigInteger.TEN), asymmetricEcKey.privateKey);

        String stringEcPoint = CustomTypeConverter.convertECPointToString(ecPoint);

        ECPoint convertedECPoint = CustomTypeConverter.convertStringToECPoint(ecPoint.getCurve(), stringEcPoint);
        assertEquals(ecPoint, convertedECPoint);
    }

    @Test
    public void encodeDecodeTest(){
        // Testing on simple Object, as a String
        String clearString = "Simple value";
        String clearStringToBase64 = CustomTypeConverter.convertObjectToString(clearString);
        assertEquals(clearString, CustomTypeConverter.convertStringToObject(clearStringToBase64, String.class));

        // Testing on BigInteger
        BigInteger clearBigInteger = CustomTypeConverter.convertStringToBigInteger("BigInteger value");
        String clearBigIntegerToBase64 = CustomTypeConverter.convertObjectToString(clearBigInteger);
        assertEquals(clearBigInteger, CustomTypeConverter.convertStringToObject(clearBigIntegerToBase64, BigInteger.class));

        // Testing con complex object
        BigInteger randomValue = CustomTypeConverter.convertStringToBigInteger("Random value");
        BigInteger encryptedValue = CustomTypeConverter.convertStringToBigInteger("Encrypted value");
        RandomEncryptedCacheObject clearObject = new RandomEncryptedCacheObject(randomValue,encryptedValue);
        String clearObjectToBase64 = CustomTypeConverter.convertObjectToString(clearObject);
        assertEquals(clearObject, CustomTypeConverter.convertStringToObject(clearObjectToBase64, RandomEncryptedCacheObject.class));
    }
}
