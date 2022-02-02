package psi.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public enum PsiAlgorithm {

    DH(2048,4096),
    BS(2048,4096),
    ECDH(256,512),
    ECBS(256,512);

    private final List<Integer> supportedKeySize;

    public List<Integer> getSupportedKeySize(){
        return new ArrayList<>(supportedKeySize);
    }

    private PsiAlgorithm(Integer ... supportedKeySize){
        this.supportedKeySize= Arrays.asList(supportedKeySize);
    }

    public static List<PsiAlgorithmParameter> getSupportedPsiAlgorithmParameter(){
        List<PsiAlgorithmParameter> psiAlgorithmParameterList = new LinkedList<>();
        for(PsiAlgorithm psiAlgorithm : PsiAlgorithm.values())
            for (Integer keySize : psiAlgorithm.getSupportedKeySize())
                psiAlgorithmParameterList.add(new PsiAlgorithmParameter(psiAlgorithm, keySize));
        return psiAlgorithmParameterList;
    }
}
