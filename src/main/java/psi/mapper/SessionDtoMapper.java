package psi.mapper;

import psi.dto.PsiSessionDTO;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.exception.PsiServerException;
import psi.server.algorithm.bs.model.BsServerSession;
import psi.server.model.ServerSession;

import java.util.Arrays;

import static psi.server.PsiServerFactory.supportedAlgorithms;

public class SessionDtoMapper {

    public static PsiSessionDTO getSessionDtoFromServerSession(ServerSession serverSession, long sessionId){
        if(serverSession == null || serverSession.getCacheEnabled() == null || serverSession.getAlgorithm() == null
                || serverSession.getKeySize() == null)
            throw new PsiServerException("The fields algorithm, keySize and cacheEnabled of serverSession cannot be null");

        if(!Arrays.asList(supportedAlgorithms).contains(serverSession.getAlgorithm()))
            throw new PsiServerException("The algorithm in serverSession is unsupported or invalid");

        if(sessionId < 0)
            throw new PsiServerException("The input sessionId is negative but should always be positive");

        PsiSessionDTO psiSessionDTO = new PsiSessionDTO();
        psiSessionDTO.setSessionId(sessionId);
        PsiAlgorithmParameterDTO psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        psiAlgorithmParameterDTO.setAlgorithm(serverSession.getAlgorithm());
        psiAlgorithmParameterDTO.setKeySize(serverSession.getKeySize());
        psiSessionDTO.setSessionParameterDTO(psiAlgorithmParameterDTO);

        switch(serverSession.getAlgorithm()){
            case "BS":
                if(!(serverSession instanceof  BsServerSession))
                    throw new PsiServerException("The serverSession passed as input of getSessionDtoFromServerSession() should be an instance of the subclass BsServerSession");
                BsServerSession bsServerSession = (BsServerSession) serverSession;
                if(bsServerSession.getModulus() == null)
                    throw new PsiServerException("The field modulus of bsServerSection cannot be null");
                psiSessionDTO.setModulus(bsServerSession.getModulus());
                if(bsServerSession.getServerPublicKey() == null)
                    throw new PsiServerException("The field serverPublicKey of bsServerSection cannot be null");
                psiSessionDTO.setServerPublicKey(bsServerSession.getServerPublicKey());
                break;
            case "DH":

            default:
                throw new PsiServerException("The algorithm in serverSession is unsupported or invalid");
        }

        return psiSessionDTO;
    }
}
