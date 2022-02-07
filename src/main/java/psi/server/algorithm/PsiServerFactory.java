package psi.server.algorithm;

import psi.cache.PsiCacheProvider;
import psi.exception.PsiServerException;
import psi.exception.PsiServerInitException;
import psi.exception.UnsupportedKeySizeException;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.server.PsiServer;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerSession;

import java.util.Arrays;

public class PsiServerFactory {

    private PsiServerFactory() {}

    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter) throws UnsupportedKeySizeException {
        return initSessionInner(psiAlgorithmParameter, null, null);
    }

    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription) throws UnsupportedKeySizeException {
        if (psiServerKeyDescription == null) {
            throw new PsiServerInitException("Input serverKeyDescription is null");
        }

        return initSessionInner(psiAlgorithmParameter, psiServerKeyDescription, null);
    }

    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        return initSessionInner(psiAlgorithmParameter, null, psiCacheProvider);
    }

    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiServerKeyDescription == null) {
            throw new PsiServerInitException("Input serverKeyDescription is null");
        }

        return initSessionInner(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);
    }

    /**
     * Calls the static method of the specific PsiServer subclass matching the algorithm set in the PsiAlgorithmParameter
     *
     * @param psiAlgorithmParameter   contains the algorithm and the key size selected by the client
     * @param psiServerKeyDescription if not null, the algorithm uses the input keys. If null, creates a new key
     * @param psiCacheProvider        if not null, uses this object as a cache provider. If null, no cache is used
     * @return a ServerSession which is an instance of the PsiServer subclass that matches the algorithm defined
     * in the PsiAlgorithmParameter.
     */
    private static PsiServerSession initSessionInner(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiAlgorithmParameter == null || psiAlgorithmParameter.getAlgorithm() == null || psiAlgorithmParameter.getKeySize() == null)
            throw new PsiServerInitException("Input psiAlgorithmParameter or its fields are null");

        if (!Arrays.asList(PsiAlgorithm.values()).contains(psiAlgorithmParameter.getAlgorithm()))
            throw new PsiServerInitException("The algorithm defined in the input psiAlgorithmParameter is invalid or not supported");

        switch (psiAlgorithmParameter.getAlgorithm()) {
            case BS:
                return BsPsiServer.initSession(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);
            case DH:
                return DhPsiServer.initSession(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);
            case ECBS:
                return EcBsPsiServer.initSession(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);
            case ECDH:
                return EcDhPsiServer.initSession(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);

            default:
                return null;
        }
    }

    public static PsiServer loadSession(PsiServerSession psiServerSession) {
        return loadSession(psiServerSession, null);
    }

    public static PsiServer loadSession(PsiServerSession psiServerSession, PsiCacheProvider psiCacheProvider) {
        if (psiServerSession == null || psiServerSession.getCacheEnabled() == null
                || psiServerSession.getPsiAlgorithmParameter() == null
                || psiServerSession.getPsiAlgorithmParameter().getAlgorithm() == null
                || psiServerSession.getPsiAlgorithmParameter().getKeySize() == null)
            throw new PsiServerInitException("The fields cacheEnabled, algorithm and keySize of the input psiServerSession cannot be null");

        PsiAlgorithm psiAlgorithm = psiServerSession.getPsiAlgorithmParameter().getAlgorithm();
        //if (!psiAlgorithm.getSupportedKeySize().contains(psiServerSession.getPsiAlgorithmParameter().getKeySize()))
        //    throw new UnsupportedKeySizeException(psiAlgorithm, psiServerSession.getPsiAlgorithmParameter().getKeySize());

        if (psiServerSession.getCacheEnabled() && psiCacheProvider == null)
            throw new PsiServerException("The session has the cache enabled but you didn't pass an implementation of psiCacheProvider as parameter of loadSession()");

        if (!psiServerSession.getCacheEnabled() && psiCacheProvider != null)
            throw new PsiServerException("The session has the cache disabled but you still passed an implementation of psiCacheProvider as parameter of loadSession()");

        switch (psiAlgorithm) {
            case BS:
                return new BsPsiServer(psiServerSession, psiCacheProvider);

            case DH:
                return new DhPsiServer(psiServerSession, psiCacheProvider);

            case ECBS:
                return new EcBsPsiServer(psiServerSession, psiCacheProvider);

            case ECDH:
                return new EcDhPsiServer(psiServerSession, psiCacheProvider);

            default:
                return null;
        }
    }


}
