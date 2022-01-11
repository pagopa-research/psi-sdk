package psi.mapper;

import psi.dto.SessionDTO;
import psi.dto.SessionParameterDTO;
import psi.exception.CustomRuntimeException;
import psi.model.ServerSessionPayload;
import psi.utils.CustomTypeConverter;

public class SessionDtoMapper {

    public static SessionDTO getSessionDtoFromServerSessionPayload(ServerSessionPayload serverSessionPayload, long sessionId){
        if(sessionId < 0)
            throw new CustomRuntimeException("The input sessionId is negative but should always be positive");
        SessionDTO sessionDTO = new SessionDTO();
        sessionDTO.setSessionId(sessionId);
        sessionDTO.setExpiration(serverSessionPayload.getExpiration());
        sessionDTO.setModulus(CustomTypeConverter.convertBigIntegerToString(serverSessionPayload.getModulus()));
        if(serverSessionPayload.getServerPublicKey() != null)
            sessionDTO.setServerPublicKey(CustomTypeConverter.convertBigIntegerToString(serverSessionPayload.getServerPublicKey()));
        SessionParameterDTO sessionParameterDTO = new SessionParameterDTO();
        sessionParameterDTO.setAlgorithm(serverSessionPayload.getAlgorithm());
        sessionParameterDTO.setKeySize(serverSessionPayload.getKeySize());
        sessionParameterDTO.setDatatypeId(serverSessionPayload.getDatatypeId());
        sessionParameterDTO.setDatatypeDescription(serverSessionPayload.getDatatypeDescription());
        sessionDTO.setSessionParameterDTO(sessionParameterDTO);
        return sessionDTO;
    }
}
