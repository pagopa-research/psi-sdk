package psi.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import psi.exception.CustomRuntimeException;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CustomTypeConverter {

    private CustomTypeConverter() {}

    public static BigInteger convertStringToBigInteger(String s){
         return new BigInteger(s.getBytes(StandardCharsets.ISO_8859_1));
     }

     public static String convertBigIntegerToString(BigInteger b){
         return new String(b.toByteArray(), StandardCharsets.ISO_8859_1);
     }

    public static ECPoint convertStringToECPoint(ECCurve curve, String s){
        return curve.decodePoint(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    public static String convertECPointToString(ECPoint point){
        return new String(point.getEncoded(true), StandardCharsets.ISO_8859_1);
    }

    public static ECParameterSpec convertStringToECParameterSpec(String ecSpecName){
        return ECNamedCurveTable.getParameterSpec(ecSpecName);
    }

    public static String convertECParameterSpecToString(ECParameterSpec ecSpec){
        return EllipticCurve.getNameCurve(ecSpec.getCurve().getA().getFieldSize());
    }

    public static <T> String convertObjectToString(T object){
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNodeJSON = objectMapper.valueToTree(object);
        try {
            byte[] jsonNodeBytes = objectMapper.writeValueAsBytes(jsonNodeJSON);
            return Base64.getEncoder().encodeToString(jsonNodeBytes);
        } catch (JsonProcessingException e) {
            throw new CustomRuntimeException("Impossible to convert object to base64");
        }
    }

    public static <T> T convertStringToObject(String base64, Class<T> typeParameterClass){
        ObjectMapper objectMapper = new ObjectMapper();
        String decodedCursor = new String(Base64.getDecoder().decode(base64));
        try {
            JsonNode jsonNode =  new ObjectMapper().readTree(decodedCursor);
            return objectMapper.treeToValue(jsonNode, typeParameterClass);
        } catch (JsonProcessingException e) {
            throw new CustomRuntimeException("Impossible to convert base64 to object");
        }
    }
}
