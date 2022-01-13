package psi.server;

import psi.dto.SessionParameterDTO;
import psi.exception.MismatchingCacheKeyIdException;
import psi.exception.MissingCacheKeyIdException;
import psi.exception.PsiClientInitException;
import psi.cache.EncryptionCacheProvider;
import psi.exception.PsiServerInitException;
import psi.model.KeyDescription;
import psi.server.algorithm.BsPsiServer;
import psi.model.ServerSessionPayload;

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

    void enableCacheSupport(EncryptionCacheProvider encryptionCacheProvider) throws MissingCacheKeyIdException, MismatchingCacheKeyIdException;

    /**  Creates the specific server object based on the algorithm field defined in the input SessionParameterDTO */
    static PsiServer initSession(SessionParameterDTO sessionParameterDTO, KeyDescription keyDescription){
        if(!Arrays.asList(supportedAlgorithms).contains(sessionParameterDTO.getAlgorithm()))
            throw new PsiServerInitException("The algorithm defined in the input SessionParameterDTO is invalid or not supported");

        if(keyDescription != null && (keyDescription.getModulus() == null || keyDescription.getModulus().isEmpty()
                || keyDescription.getKey() == null || keyDescription.getKey().isEmpty()))
            throw new PsiServerInitException("The key and/or modulus passed in the parameter keyDescription is either null or empty");

        switch(sessionParameterDTO.getAlgorithm()){
            case "BS":
                return new BsPsiServer(sessionParameterDTO);
            case "DH":
                return null;
        }
        return null;
    }

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

    ServerSessionPayload getSessionPayload();

    void setSessionId(Long sessionId);

    Long getSessionId();

    KeyDescription getKeyDescription();

    int getThreads();

    void setThreads(int threads);
}
