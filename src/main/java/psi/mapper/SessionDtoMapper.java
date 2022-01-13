package psi.mapper;

import psi.dto.SessionDTO;
import psi.dto.SessionParameterDTO;
import psi.exception.PsiServerException;
import psi.model.BsServerSession;
import psi.model.ServerSession;

import java.util.Arrays;

import static psi.client.PsiClient.supportedAlgorithms;

public class SessionDtoMapper {

    public static SessionDTO getSessionDtoFromServerSession(ServerSession serverSession, long sessionId){
        if(serverSession == null || serverSession.getCacheEnabled() == null || serverSession.getAlgorithm() == null
                || serverSession.getKeySize() == null)
            throw new PsiServerException("The fields algorithm, keySize and cacheEnabled of serverSession cannot be null");

        if(!Arrays.asList(supportedAlgorithms).contains(serverSession.getAlgorithm()))
            throw new PsiServerException("The algorithm in serverSession is unsupported or invalid");

        if(sessionId < 0)
            throw new PsiServerException("The input sessionId is negative but should always be positive");

        SessionDTO sessionDTO = new SessionDTO();
        sessionDTO.setSessionId(sessionId);
        SessionParameterDTO sessionParameterDTO = new SessionParameterDTO();
        sessionParameterDTO.setAlgorithm(serverSession.getAlgorithm());
        sessionParameterDTO.setKeySize(serverSession.getKeySize());
        sessionDTO.setSessionParameterDTO(sessionParameterDTO);
        sessionDTO.setCacheEnabled(serverSession.getCacheEnabled());

        switch(serverSession.getAlgorithm()){
            case "BS":
                if(!(serverSession instanceof  BsServerSession))
                    throw new PsiServerException("The serverSession passed as input of getSessionDtoFromServerSession() should be an instance of the subclass BsServerSession");
                BsServerSession bsServerSession = (BsServerSession) serverSession;
                if(bsServerSession.getModulus() == null)
                    throw new PsiServerException("The field modulus of bsServerSection cannot be null");
                sessionDTO.setModulus(bsServerSession.getModulus());
                if(bsServerSession.getServerPublicKey() == null)
                    throw new PsiServerException("The field serverPublicKey of bsServerSection cannot be null");
                sessionDTO.setServerPublicKey(bsServerSession.getServerPublicKey());
                break;
            case "DH":

            default:
                throw new PsiServerException("The algorithm in serverSession is unsupported or invalid");
        }

        return sessionDTO;
    }
}
