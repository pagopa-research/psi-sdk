package psi.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 * Lists all the supported PSI algorithms and the respective supported key sizes.
 */

public enum PsiAlgorithm {

    DH(2048, 3072, 4096, 8192),
    BS(2048, 3072, 4096, 8192),
    ECDH(224, 256, 384, 512),
    ECBS(224, 256, 384, 512);

    private final List<Integer> supportedKeySize;

    public List<Integer> getSupportedKeySize() {
        return new ArrayList<>(supportedKeySize);
    }

    PsiAlgorithm(Integer... supportedKeySize) {
        this.supportedKeySize = Arrays.asList(supportedKeySize);
    }

    public static List<PsiAlgorithmParameter> getSupportedPsiAlgorithmParameter(){
        List<PsiAlgorithmParameter> psiAlgorithmParameterList = new LinkedList<>();
        for(PsiAlgorithm psiAlgorithm : PsiAlgorithm.values())
            for (Integer keySize : psiAlgorithm.getSupportedKeySize())
                psiAlgorithmParameterList.add(new PsiAlgorithmParameter(psiAlgorithm, keySize));
        return psiAlgorithmParameterList;
    }
}
