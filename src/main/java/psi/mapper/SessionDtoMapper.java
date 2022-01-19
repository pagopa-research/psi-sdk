package psi.mapper;

import psi.dto.PsiSessionDTO;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.exception.PsiServerException;
import psi.server.algorithm.bs.model.BsPsiServerSession;
import psi.server.model.PsiServerSession;

import java.util.Arrays;

import static psi.server.PsiServerFactory.supportedAlgorithms;

public class SessionDtoMapper {

    public static PsiSessionDTO getSessionDtoFromServerSession(PsiServerSession psiServerSession){
        if(psiServerSession == null || psiServerSession.getCacheEnabled() == null || psiServerSession.getAlgorithm() == null
                || psiServerSession.getKeySize() == null)
            throw new PsiServerException("The fields algorithm, keySize and cacheEnabled of psiServerSession cannot be null");

        if(!Arrays.asList(supportedAlgorithms).contains(psiServerSession.getAlgorithm()))
            throw new PsiServerException("The algorithm in psiServerSession is unsupported or invalid");

        PsiSessionDTO psiSessionDTO = new PsiSessionDTO();
        PsiAlgorithmParameterDTO psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        psiAlgorithmParameterDTO.setAlgorithm(AlgorithmMapper.toDTO(psiServerSession.getAlgorithm()));
        psiAlgorithmParameterDTO.setKeySize(psiServerSession.getKeySize());
        psiSessionDTO.setPsiAlgorithmParameterDTO(psiAlgorithmParameterDTO);

        switch(psiServerSession.getAlgorithm()){
            case "BS":
                if(!(psiServerSession instanceof BsPsiServerSession))
                    throw new PsiServerException("The psiServerSession passed as input of getSessionDtoFromServerSession() should be an instance of the subclass BsServerSession");
                BsPsiServerSession bsServerSession = (BsPsiServerSession) psiServerSession;
                if(bsServerSession.getModulus() == null)
                    throw new PsiServerException("The field modulus of bsServerSection cannot be null");
                psiSessionDTO.setModulus(bsServerSession.getModulus());
                if(bsServerSession.getServerPublicKey() == null)
                    throw new PsiServerException("The field serverPublicKey of bsServerSection cannot be null");
                psiSessionDTO.setServerPublicKey(bsServerSession.getServerPublicKey());
                break;
            case "DH":

            default:
                throw new PsiServerException("The algorithm in psiServerSession is unsupported or invalid");
        }

        return psiSessionDTO;
    }
}
