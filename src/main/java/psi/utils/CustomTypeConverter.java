package psi.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class CustomTypeConverter {

     public static BigInteger convertStringToBigInteger(String s){
         return new BigInteger(s.getBytes(StandardCharsets.ISO_8859_1));
     }

     public static String convertBigIntegerToString(BigInteger b){
         return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
     }
}
