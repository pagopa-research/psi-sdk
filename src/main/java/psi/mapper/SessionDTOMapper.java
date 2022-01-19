package psi.mapper;

import psi.dto.PsiSessionDTO;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.exception.CustomRuntimeException;
import psi.exception.PsiServerException;
import psi.server.PsiServerSession;

import java.util.Arrays;

import static psi.server.PsiServerFactory.supportedAlgorithms;

public class SessionDTOMapper {

    public static PsiSessionDTO getSessionDtoFromServerSession(PsiServerSession psiServerSession){
        if(psiServerSession == null || psiServerSession.getCacheEnabled() == null || psiServerSession.getAlgorithm() == null
                || psiServerSession.getKeySize() == null)
            throw new PsiServerException("The fields algorithm, keySize and cacheEnabled of psiServerSession cannot be null");

        if(psiServerSession.getPsiServerKeyDescription() == null)
            throw new CustomRuntimeException("The PsiServerKeyDescription of the psiServerSession should not be null");

        if(!Arrays.asList(supportedAlgorithms).contains(psiServerSession.getAlgorithm()))
            throw new PsiServerException("The algorithm in psiServerSession is unsupported or invalid");

        PsiSessionDTO psiSessionDTO = new PsiSessionDTO();
        PsiAlgorithmParameterDTO psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        psiAlgorithmParameterDTO.setAlgorithm(AlgorithmDTOMapper.toDTO(psiServerSession.getAlgorithm()));
        psiAlgorithmParameterDTO.setKeySize(psiServerSession.getKeySize());
        psiSessionDTO.setPsiAlgorithmParameterDTO(psiAlgorithmParameterDTO);

        switch(psiServerSession.getAlgorithm()){
            case "BS":
                if(psiServerSession.getPsiServerKeyDescription().getModulus() == null)
                    throw new PsiServerException("The field modulus of psiServerKeyDescription cannot be null");
                psiSessionDTO.setModulus(psiServerSession.getPsiServerKeyDescription().getModulus());
                if(psiServerSession.getPsiServerKeyDescription().getPublicKey() == null)
                    throw new PsiServerException("The field publicKey of psiServerKeyDescription cannot be null");
                psiSessionDTO.setServerPublicKey(psiServerSession.getPsiServerKeyDescription().getPublicKey());
                break;
            case "DH":

            default:
                throw new PsiServerException("The algorithm in psiServerSession is unsupported or invalid");
        }

        return psiSessionDTO;
    }
}
