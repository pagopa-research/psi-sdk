package psi.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public enum PsiAlgorithm {

    DH(2048,4096),
    BS(2048,4096);

    private final List<Integer> supportedKeySize;

    public List<Integer> getSupportedKeySize(){
        return new ArrayList<>(supportedKeySize);
    }

    private PsiAlgorithm(Integer ... supportedKeySize){
        this.supportedKeySize= Arrays.asList(supportedKeySize);
    }
}
