package psi.server;

import psi.cache.EncryptionCacheProvider;
import psi.dto.SessionParameterDTO;
import psi.exception.PsiServerInitException;
import psi.exception.PsiServerException;
import psi.model.BsKeyDescription;
import psi.model.BsServerSession;
import psi.model.KeyDescription;
import psi.model.ServerSession;
import psi.server.algorithm.BsPsiServer;

import java.util.Arrays;

public class PsiServerFactory {

    static String[] supportedAlgorithms =
            {
                    "BS",
                    "ECBS",
                    "DH",
                    "ECDH"
            };

    public static ServerSession initSession(SessionParameterDTO sessionParameterDTO) {
        return initSessionInner(sessionParameterDTO, null, null);
    }

    public static ServerSession initSession(SessionParameterDTO sessionParameterDTO, KeyDescription keyDescription) {
        if (keyDescription == null) {
            throw new PsiServerInitException("Input keyDescription is null");
        }

        return initSessionInner(sessionParameterDTO, keyDescription, null);
    }

    public static ServerSession initSession(SessionParameterDTO sessionParameterDTO, KeyDescription keyDescription, EncryptionCacheProvider encryptionCacheProvider) {
        if (keyDescription == null) {
            throw new PsiServerInitException("Input keyDescription is null");
        }

        if (encryptionCacheProvider == null) {
            throw new PsiServerInitException("Input encryptionCacheProvider is null");
        }

        return initSessionInner(sessionParameterDTO, keyDescription, encryptionCacheProvider);
    }

    /**
     *  Calls the static method of the specific PsiServer subclass matching the algorithm set in the sessionParameterDTO
     * @param sessionParameterDTO contains the algorithm and the key size selected by the client
     * @param keyDescription if not null, the algorithm uses the input keys. If null, creates a new key
     * @param encryptionCacheProvider if not null, uses this object as a cache provider. If null, no cache is used
     *
     * @return a ServerSession which is an instance of the PsiServer subclass that matches the algorithm defined
     * in the sessionParameter DTO.
     */
    private static ServerSession initSessionInner(SessionParameterDTO sessionParameterDTO, KeyDescription keyDescription, EncryptionCacheProvider encryptionCacheProvider) {
        if (sessionParameterDTO == null || sessionParameterDTO.getAlgorithm() == null
                || sessionParameterDTO.getAlgorithm().isEmpty() || sessionParameterDTO.getKeySize() == null)
            throw new PsiServerInitException("Input sessionParameterDTO is null");

        if (!Arrays.asList(supportedAlgorithms).contains(sessionParameterDTO.getAlgorithm()))
            throw new PsiServerInitException("The algorithm defined in the input SessionParameterDTO is invalid or not supported");

        switch (sessionParameterDTO.getAlgorithm()) {
            case "BS":
                if (keyDescription != null && !(keyDescription instanceof BsKeyDescription))
                    throw new PsiServerInitException("The subclass of the input keyDescription does not match the algorithm. Should pass as keyDescription an instance of BsKeyDescription.");
                return BsPsiServer.initSession(sessionParameterDTO, keyDescription != null ? (BsKeyDescription) keyDescription : null, encryptionCacheProvider);

            case "DH":

            default:
                return null;
        }
    }

    public static PsiServer loadSession(ServerSession serverSession){
        return loadSession(serverSession, null);
    }

    public static PsiServer loadSession(ServerSession serverSession, EncryptionCacheProvider encryptionCacheProvider) {
        if (serverSession == null || serverSession.getCacheEnabled() == null || serverSession.getAlgorithm() == null || serverSession.getKeySize() == null)
            throw new PsiServerInitException("The fields cacheEnabled, algorithm and keySize of the input serverSession cannot be null");

        if (serverSession.getCacheEnabled() && encryptionCacheProvider == null)
            throw new PsiServerException("The session has the cache enabled but you didn't pass an implementation of encryptionCacheProvider as parameter of loadSession()");

        if(serverSession.getCacheEnabled() && serverSession.getKeyId() == null){
            throw new PsiServerException("The field keyId of serverSession cannot be null if the cache is enabled");
        }

        if (!serverSession.getCacheEnabled() && encryptionCacheProvider != null)
            throw new PsiServerException("The session has the cache disabled but you still passed an implementation of encryptionCacheProvider as parameter of loadSession()");

        switch (serverSession.getAlgorithm()) {
            case "BS":
                if (!(serverSession instanceof BsServerSession))
                    throw new PsiServerInitException("The subclass of the input serverSession does not match the algorithm. Should pass as serverSession an instance of BsServerSession.");
                return new BsPsiServer((BsServerSession) serverSession, encryptionCacheProvider);

            case "DH":

            default:
                return null;
        }
    }


}
