package psi.utils;

import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class CustomTypeConverterTest {

    private boolean isBigIntegerConversionBidirectional(String s) throws UnsupportedEncodingException {
        BigInteger stringToBigInteger = CustomTypeConverter.convertStringToBigInteger(s);
        String bigIntegerToString = CustomTypeConverter.convertBigIntegerToString(stringToBigInteger);
        return s.equals(bigIntegerToString);
    }

    @Test
    public void bigIntegerConversionTest() throws UnsupportedEncodingException {
        String s1 = "BasicString1";
        String s2 = "40232931320130013020";
        String s3 = "Rather complex string!*$%";
        String s4 = "String with multiple lines\ncan be tricky\n";
        StringBuilder stringBuilder = new StringBuilder();
        for(int i = 0; i< 100000; i++){
            stringBuilder.append("SuperLongString!");
        }
        String s5 = stringBuilder.toString();

        assertTrue(isBigIntegerConversionBidirectional(s1));
        assertTrue(isBigIntegerConversionBidirectional(s2));
        assertTrue(isBigIntegerConversionBidirectional(s3));
        assertTrue(isBigIntegerConversionBidirectional(s4));
        assertTrue(isBigIntegerConversionBidirectional(s5));
    }
}
