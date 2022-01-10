package psi.client;

import psi.client.algorithm.BsPsiClient;
import psi.dto.SessionDTO;
import psi.exception.PsiClientInitException;
import psi.pluggable.EncryptionCacheProvider;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

public interface PsiClient {

    String[] supportedAlgorithms =
        {
            "BS",
            "DH"
        };

    Map<Long, String> loadAndEncryptClientDataset(Map<Long, String> clearClientDataset);

    void loadDoubleEncryptedClientDataset(Map<Long, String> doubleEncryptedClientDatasetMap);

    void loadServerDataset(Set<String> serverEncryptedDataset);

    Set<String> computePsi();

    void enableCacheSupport(EncryptionCacheProvider encryptionCacheProvider);

    /**  Creates the specific client object based on the algorithm field defined in the input sessionDTO */
    static PsiClient initSession(SessionDTO sessionDTO){
        if(sessionDTO.getSessionId() == null || sessionDTO.getSessionId() <= 0)
            throw new PsiClientInitException("The id of the input sessionDTO is invalid");

        if(!Arrays.asList(supportedAlgorithms).contains(sessionDTO.getSessionParameterDTO().getAlgorithm()))
            throw new PsiClientInitException("The algorithm defined in the input sessionDTO is invalid or not supported");

        switch(sessionDTO.getSessionParameterDTO().getAlgorithm()){
            case "BS":
                return new BsPsiClient(sessionDTO);
            case "DH":
                return null;
        }
        return null;
    }

}
