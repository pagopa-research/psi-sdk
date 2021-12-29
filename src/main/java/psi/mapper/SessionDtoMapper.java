package psi.mapper;

import psi.dto.SessionDTO;
import psi.dto.SessionParameterDTO;
import psi.exception.CustomRuntimeException;
import psi.server.model.SessionPayload;
import psi.utils.CustomTypeConverter;

public class SessionDtoMapper {

    public static SessionDTO getSessionDtoFromSessionPayload(SessionPayload sessionPayload, long sessionId){
        if(sessionId < 0)
            throw new CustomRuntimeException("The input sessionId is negative but should always be positive");
        SessionDTO sessionDTO = new SessionDTO();
        sessionDTO.setSessionId(sessionId);
        sessionDTO.setExpiration(sessionPayload.getExpiration());
        sessionDTO.setModulus(CustomTypeConverter.convertBigIntegerToString(sessionPayload.getModulus()));
        if(sessionPayload.getServerPublicKey() != null)
            sessionDTO.setServerPublicKey(CustomTypeConverter.convertBigIntegerToString(sessionPayload.getServerPublicKey()));
        SessionParameterDTO sessionParameterDTO = new SessionParameterDTO();
        sessionParameterDTO.setAlgorithm(sessionPayload.getAlgorithm());
        sessionParameterDTO.setKeySize(sessionPayload.getKeySize());
        sessionParameterDTO.setDatatypeId(sessionPayload.getDatatypeId());
        sessionParameterDTO.setDatatypeDescription(sessionPayload.getDatatypeDescription());
        sessionDTO.setSessionParameterDTO(sessionParameterDTO);
        return sessionDTO;
    }
}
