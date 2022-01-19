package psi.server;

import psi.cache.PsiCacheProvider;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.exception.PsiServerInitException;
import psi.exception.PsiServerException;
import psi.server.algorithm.bs.model.BsPsiServerKeyDescription;
import psi.server.algorithm.bs.model.BsPsiServerSession;
import psi.server.model.PsiServerKeyDescription;
import psi.server.model.PsiServerSession;
import psi.server.algorithm.bs.BsPsiServer;

import java.util.Arrays;

public class PsiServerFactory {

    public static String[] supportedAlgorithms =
            {
                    "BS",
                    "ECBS",
                    "DH",
                    "ECDH"
            };

    public static PsiServerSession initSession(PsiAlgorithmParameterDTO psiAlgorithmParameterDTO) {
        return initSessionInner(psiAlgorithmParameterDTO, null, null);
    }

    public static PsiServerSession initSession(PsiAlgorithmParameterDTO psiAlgorithmParameterDTO, PsiServerKeyDescription psiServerKeyDescription) {
        if (psiServerKeyDescription == null) {
            throw new PsiServerInitException("Input serverKeyDescription is null");
        }

        return initSessionInner(psiAlgorithmParameterDTO, psiServerKeyDescription, null);
    }

    public static PsiServerSession initSession(PsiAlgorithmParameterDTO psiAlgorithmParameterDTO, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) {
        if (psiServerKeyDescription == null) {
            throw new PsiServerInitException("Input serverKeyDescription is null");
        }

        if (psiCacheProvider == null) {
            throw new PsiServerInitException("Input psiCacheProvider is null");
        }

        return initSessionInner(psiAlgorithmParameterDTO, psiServerKeyDescription, psiCacheProvider);
    }

    /**
     *  Calls the static method of the specific PsiServer subclass matching the algorithm set in the sessionParameterDTO
     * @param psiAlgorithmParameterDTO contains the algorithm and the key size selected by the client
     * @param psiServerKeyDescription if not null, the algorithm uses the input keys. If null, creates a new key
     * @param psiCacheProvider if not null, uses this object as a cache provider. If null, no cache is used
     *
     * @return a ServerSession which is an instance of the PsiServer subclass that matches the algorithm defined
     * in the sessionParameter DTO.
     */
    private static PsiServerSession initSessionInner(PsiAlgorithmParameterDTO psiAlgorithmParameterDTO, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) {
        if (psiAlgorithmParameterDTO == null || psiAlgorithmParameterDTO.getAlgorithm() == null || psiAlgorithmParameterDTO.getKeySize() == null)
            throw new PsiServerInitException("Input PsiAlgorithmParameterDTO is null");

        if (!Arrays.asList(supportedAlgorithms).contains(psiAlgorithmParameterDTO.getAlgorithm().toString()))
            throw new PsiServerInitException("The algorithm defined in the input SessionParameterDTO is invalid or not supported");

        switch (psiAlgorithmParameterDTO.getAlgorithm()) {
            case BS:
                if (psiServerKeyDescription != null && !(psiServerKeyDescription instanceof BsPsiServerKeyDescription))
                    throw new PsiServerInitException("The subclass of the input serverKeyDescription does not match the algorithm. Should pass as serverKeyDescription an instance of BsServerKeyDescription.");
                return BsPsiServer.initSession(psiAlgorithmParameterDTO, psiServerKeyDescription != null ? (BsPsiServerKeyDescription) psiServerKeyDescription : null, psiCacheProvider);

            case DH:

            default:
                return null;
        }
    }

    public static PsiServer loadSession(PsiServerSession psiServerSession){
        return loadSession(psiServerSession, null);
    }

    public static PsiServer loadSession(PsiServerSession psiServerSession, PsiCacheProvider psiCacheProvider) {
        if (psiServerSession == null || psiServerSession.getCacheEnabled() == null || psiServerSession.getAlgorithm() == null || psiServerSession.getKeySize() == null)
            throw new PsiServerInitException("The fields cacheEnabled, algorithm and keySize of the input serverSession cannot be null");

        if (psiServerSession.getCacheEnabled() && psiCacheProvider == null)
            throw new PsiServerException("The session has the cache enabled but you didn't pass an implementation of psiCacheProvider as parameter of loadSession()");

        if(psiServerSession.getCacheEnabled() && psiServerSession.getKeyId() == null){
            throw new PsiServerException("The field keyId of serverSession cannot be null if the cache is enabled");
        }

        if (!psiServerSession.getCacheEnabled() && psiCacheProvider != null)
            throw new PsiServerException("The session has the cache disabled but you still passed an implementation of psiCacheProvider as parameter of loadSession()");

        switch (psiServerSession.getAlgorithm()) {
            case "BS":
                if (!(psiServerSession instanceof BsPsiServerSession))
                    throw new PsiServerInitException("The subclass of the input serverSession does not match the algorithm. Should pass as serverSession an instance of BsServerSession.");
                return new BsPsiServer((BsPsiServerSession) psiServerSession, psiCacheProvider);

            case "DH":

            default:
                return null;
        }
    }


}
