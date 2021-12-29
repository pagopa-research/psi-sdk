package psi.utils;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

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
}
