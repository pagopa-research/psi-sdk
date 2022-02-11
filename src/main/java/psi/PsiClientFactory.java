package psi;

import psi.cache.PsiCacheProvider;
import psi.client.PsiClient;
import psi.exception.PsiClientException;
import psi.exception.UnsupportedKeySizeException;
import psi.model.PsiAlgorithm;
import psi.model.PsiClientSession;

import java.util.Arrays;

public class PsiClientFactory {

    private PsiClientFactory() {}

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession) throws UnsupportedKeySizeException {
        return loadSessionInner(psiClientSession, null, null);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription) throws UnsupportedKeySizeException {
        if (psiClientKeyDescription == null) {
            throw new PsiClientException("Input clientKeyDescription is null");
        }

        return loadSessionInner(psiClientSession, psiClientKeyDescription, null);
    }

    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiClientSession, null, psiCacheProvider);
    }

    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiClientKeyDescription == null)
            throw new PsiClientException("Input clientKeyDescription is null");

        if (psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiClientSession, psiClientKeyDescription, psiCacheProvider);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession
     */
    private static PsiClient loadSessionInner(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (!Arrays.asList(PsiAlgorithm.values()).contains(psiClientSession.getPsiAlgorithmParameter().getAlgorithm()))
            throw new PsiClientException("The algorithm defined in the input psiClientSession is invalid or not supported");

        PsiAlgorithm psiAlgorithm = psiClientSession.getPsiAlgorithmParameter().getAlgorithm();
        if (!psiAlgorithm.getSupportedKeySize().contains(psiClientSession.getPsiAlgorithmParameter().getKeySize()))
            throw new UnsupportedKeySizeException(psiAlgorithm, psiClientSession.getPsiAlgorithmParameter().getKeySize());

        switch (psiAlgorithm) {
            case BS:
                return new PsiClientBs(psiClientSession, psiClientKeyDescription, psiCacheProvider);
            case DH:
                return new PsiClientDh(psiClientSession, psiClientKeyDescription, psiCacheProvider);
            case ECBS:
                return new PsiClientEcBs(psiClientSession, psiClientKeyDescription, psiCacheProvider);
            case ECDH:
                return new PsiClientEcDh(psiClientSession, psiClientKeyDescription, psiCacheProvider);

            default:
                return null;
        }
    }
}
