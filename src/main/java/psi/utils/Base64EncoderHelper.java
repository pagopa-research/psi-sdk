package psi.utils;

import java.util.Base64;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import psi.exception.CustomRuntimeException;

public class Base64EncoderHelper {

    private Base64EncoderHelper(){}

    public static <T> String objectToBase64(T dto){
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNodeJSON = objectMapper.valueToTree(dto);
        try {
            byte[] jsonNodeBytes = objectMapper.writeValueAsBytes(jsonNodeJSON);
            return Base64.getEncoder().encodeToString(jsonNodeBytes);
        } catch (JsonProcessingException e) {
            throw new CustomRuntimeException("Impossible to convert object to base64");
        }
    }

    public static <T> T base64ToObject(String base64, Class<T> typeParameterClass){
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
