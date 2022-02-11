package psi;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.exception.CustomRuntimeException;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * This class offers a series of utilities to convert object from/to a String representation, useful to store and/or
 * transfer them while hiding the internal complexity of the objects used by the sdk.
 */
class CustomTypeConverter {

    private static final Logger log = LoggerFactory.getLogger(CustomTypeConverter.class);

    private CustomTypeConverter() {}

    private static final Charset charset = StandardCharsets.ISO_8859_1;

    static BigInteger convertStringToBigInteger(String string){
        log.trace("Called convertStringToBigInteger() with string = {}", string);
         return new BigInteger(string.getBytes(charset));
     }

     static String convertBigIntegerToString(BigInteger bigInteger){
         log.trace("Called convertBigIntegerToString() with bigInteger = {}", bigInteger);
         return new String(bigInteger.toByteArray(), charset);
     }

    static ECPoint convertStringToECPoint(ECCurve curve, String string){
        log.trace("Called convertStringToECPoint() with curve = {}, string = {}", curve, string);
        return curve.decodePoint(string.getBytes(charset));
    }

    static String convertECPointToString(ECPoint point){
        log.trace("Called convertECPointToString() with point = {}", point);
        return new String(point.getEncoded(true), charset);
    }

    static ECParameterSpec convertKeySizeToECParameterSpec(Integer keySize){
        log.trace("Called convertKeySizeToECParameterSpec() with keySize = {}", keySize);
        return ECNamedCurveTable.getParameterSpec(EllipticCurve.getNameCurve(keySize));
    }

    static String convertECParameterSpecToString(ECParameterSpec ecSpec){
        log.trace("Called convertECParameterSpecToString() with ecSpec = {}", ecSpec);
        return EllipticCurve.getNameCurve(ecSpec.getCurve().getA().getFieldSize());
    }

    static <T> String convertObjectToString(T object){
        log.trace("Called convertObjectToString() with object = {}", object);
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        JsonNode jsonNodeJSON = objectMapper.valueToTree(object);
        try {
            byte[] jsonNodeBytes = objectMapper.writeValueAsBytes(jsonNodeJSON);
            return Base64.getEncoder().encodeToString(jsonNodeBytes);
        } catch (JsonProcessingException e) {
            throw new CustomRuntimeException("Impossible to convert object to base64");
        }
    }

    static <T> T convertStringToObject(String base64, Class<T> typeParameterClass){
        log.trace("Called convertStringToObject() with base64 = {}, typeParameterClass = {}", base64, typeParameterClass);
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        String decodedCursor = new String(Base64.getDecoder().decode(base64));
        try {
            JsonNode jsonNode =  new ObjectMapper().readTree(decodedCursor);
            return objectMapper.treeToValue(jsonNode, typeParameterClass);
        } catch (JsonProcessingException e) {
            throw new CustomRuntimeException("Impossible to convert base64 to object");
        }
    }
}
