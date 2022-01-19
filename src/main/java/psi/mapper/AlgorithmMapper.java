package psi.mapper;

import psi.dto.PsiAlgorithmDTO;
import psi.exception.CustomRuntimeException;

public class AlgorithmMapper {

    public static String toString(PsiAlgorithmDTO algorithmDTO){
        return algorithmDTO.toString();
    }

    public static PsiAlgorithmDTO toDTO(String algorithm){
        switch (algorithm) {
            case "DH":
                return PsiAlgorithmDTO.DH;
            case "BS":
                return PsiAlgorithmDTO.BS;
            default:
                throw new CustomRuntimeException("Algorithm not supported");
        }
    }
}
