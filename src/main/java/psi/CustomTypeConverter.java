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
 * Provides methods that convert complex objects from/to a String representation, which is useful to store and/or
 * transfer them while hiding the internal complexity of the objects used by the sdk.
 */
class CustomTypeConverter {

    private static final Logger log = LoggerFactory.getLogger(CustomTypeConverter.class);

    private CustomTypeConverter() {}

    private static final Charset charset = StandardCharsets.ISO_8859_1;

    /**
     * Converts a String value into a BigInteger.
     * @param string String representation of the BigInteger value
     * @return the BigInteger representation of the String based on the selected charset
     */
    static BigInteger convertStringToBigInteger(String string){
        log.trace("Called convertStringToBigInteger() with string = {}", string);
         return new BigInteger(string.getBytes(charset));
     }

    /**
     * Converts a BigInteger value into a String.
     * @param bigInteger BigInteger value to be converted
     * @return the String representation of the BigInteger based on the selected charset
     */
     static String convertBigIntegerToString(BigInteger bigInteger){
         log.trace("Called convertBigIntegerToString() with bigInteger = {}", bigInteger);
         return new String(bigInteger.toByteArray(), charset);
     }

    /**
     * Converts a String value into an ECPoint.
     * @param curve     curve used to convert the string into a point
     * @param string    String representation of the ECPoint value
     * @return the ECPoint obtained converting the String on the provided curve
     */
    static ECPoint convertStringToECPoint(ECCurve curve, String string){
        log.trace("Called convertStringToECPoint() with curve = {}, string = {}", curve, string);
        return curve.decodePoint(string.getBytes(charset));
    }

    /**
     * Converts an ECPoint value into a String.
     * @param point ECPoint value to be converted
     * @return the String representation of the ECPoint
     */
    static String convertECPointToString(ECPoint point){
        log.trace("Called convertECPointToString() with point = {}", point);
        return new String(point.getEncoded(true), charset);
    }

    /**
     * Converts a key size value into an ECParameterSpec.
     * @param keySize size of the key
     * @return the ECParameterSpec obtained from the provided key size
     */
    static ECParameterSpec convertKeySizeToECParameterSpec(Integer keySize){
        log.trace("Called convertKeySizeToECParameterSpec() with keySize = {}", keySize);
        return ECNamedCurveTable.getParameterSpec(EllipticCurve.getNameCurve(keySize));
    }

    /**
     * Converts a generic Serializable Object into a string.
     * @param object object to be serialized
     * @return the serialized String representation of object
     */
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

    /**
     * Converts a String value into an Object of class T.
     * @param string         serialized String representation of the object
     * @param typeParamClass class of the object to be retrieved
     * @return the object obtained converting the String based on the specified class
     */
    static <T> T convertStringToObject(String string, Class<T> typeParamClass){
        log.trace("Called convertStringToObject() with string = {}, typeParamClass = {}", string, typeParamClass);
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
        String decodedCursor = new String(Base64.getDecoder().decode(string));
        try {
            JsonNode jsonNode =  new ObjectMapper().readTree(decodedCursor);
            return objectMapper.treeToValue(jsonNode, typeParamClass);
        } catch (JsonProcessingException e) {
            throw new CustomRuntimeException("Impossible to convert string to object");
        }
    }
}
