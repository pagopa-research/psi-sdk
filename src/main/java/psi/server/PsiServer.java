package psi.server;

import psi.dto.SessionParameterDTO;
import psi.exception.PsiClientInitException;
import psi.pluggable.EncryptionCacheProvider;
import psi.server.algorithm.BsPsiServer;
import psi.server.model.SessionPayload;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

public interface PsiServer {

    String[] supportedAlgorithms =
            {
                    "BS",
                    "DH"
            };

    Set<String> encryptDataset(BigInteger serverPrivateKey, BigInteger modulus, Set<String> inputSet);

    Map<Long, String> encryptDatasetMap(BigInteger serverPrivateKey, BigInteger modulus,  Map<Long, String> encryptedDatasetMap);

    void enableCacheSupport(EncryptionCacheProvider encryptionCacheProvider);

    /**  Creates the specific server object based on the algorithm field defined in the input SessionParameterDTO */
    static PsiServer initSession(SessionParameterDTO sessionParameterDTO){
        if(!Arrays.asList(supportedAlgorithms).contains(sessionParameterDTO.getAlgorithm()))
            throw new PsiClientInitException("The algorithm defined in the input SessionParameterDTO is invalid or not supported");

        switch(sessionParameterDTO.getAlgorithm()){
            case "BS":
                return new BsPsiServer(sessionParameterDTO);
            case "DH":
                return null;
        }
        return null;
    }

    SessionPayload getSessionPayload();

    void setSessionId(Long sessionId);

    Long getSessionId();

    public int getThreads();

    public void setThreads(int threads);
}
