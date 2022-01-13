package psi.utils;

import java.util.Base64;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Base64EncoderHelper {

    static public <T> String dtoToBase64(T dto){
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNodeJSON = objectMapper.valueToTree(dto);
        try {
            byte[] jsonNodeBytes = objectMapper.writeValueAsBytes(jsonNodeJSON);
            return Base64.getEncoder().encodeToString(jsonNodeBytes);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new RuntimeException("Impossible to convert object to base64");
        }
    }

    static public <T> T base64ToDto(String base64, Class<T> typeParameterClass){
        ObjectMapper objectMapper = new ObjectMapper();
        String decodedCursor = new String(Base64.getDecoder().decode(base64));
        try {
            JsonNode jsonNode =  new ObjectMapper().readTree(decodedCursor);
            return objectMapper.treeToValue(jsonNode, typeParameterClass);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new RuntimeException("Impossible to convert base64 to object");
        }

    }

}
