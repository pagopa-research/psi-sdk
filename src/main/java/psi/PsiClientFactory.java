package psi;

import psi.cache.PsiCacheProvider;
import psi.client.PsiClient;
import psi.exception.PsiClientException;
import psi.exception.UnsupportedKeySizeException;
import psi.model.PsiAlgorithm;
import psi.model.PsiClientSession;

import java.util.Arrays;

/**
 * This class offers to the user a generic interface to load a specific PsiClient implementation and configuration
 * depending on the provided inputs (client session, key description and cache provider).
 */
public class PsiClientFactory {

    private PsiClientFactory() {}

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession.
     * @param psiClientSession containing the information sent from the server to correctly initialize the client
     * @return a PsiClient instance configured respect to the input parameter
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession) throws UnsupportedKeySizeException {
        return loadSessionInner(psiClientSession, null, null);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession, and
     * externally setup the psiClientKeyDescription used by the computation.
     * @param psiClientSession          containing the information sent from the server to correctly initialize the client
     * @param psiClientKeyDescription   containing the information used to perform encryption operations (e.g. exponent of the private key)
     * @return a PsiClient instance configured respect to the input parameters
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription) throws UnsupportedKeySizeException {
        if (psiClientKeyDescription == null) {
            throw new PsiClientException("Input clientKeyDescription is null");
        }

        return loadSessionInner(psiClientSession, psiClientKeyDescription, null);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession. Since a
     * PsiCacheProvider implementation is passed, the cache support in automatically enabled.
     * @param psiClientSession  containing the information sent from the server to correctly initialize the client
     * @param psiCacheProvider  implementation of the psiCacheProvider
     * @return a PsiClient instance configured respect to the input parameters
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiClientSession, null, psiCacheProvider);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession, and
     * externally setup the psiClientKeyDescription used by the computation. Since a PsiCacheProvider implementation is
     * passed, the cache support in automatically enabled.
     * @param psiClientSession          containing the information sent from the server to correctly initialize the client
     * @param psiClientKeyDescription   containing the information used to perform encryption operations (e.g. exponent of the private key)
     * @param psiCacheProvider          implementation of the psiCacheProvider
     * @return a PsiClient instance configured respect to the input parameters
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiClientKeyDescription == null)
            throw new PsiClientException("Input clientKeyDescription is null");

        if (psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiClientSession, psiClientKeyDescription, psiCacheProvider);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession. If a
     * PsiCacheProvider implementation is passed, the cache support in automatically enabled. It is not offered to the
     * user and is used by loadSession methods to select the correct PsiClient implementation.
     * @param psiClientSession          containing the information sent from the server to correctly initialize the client
     * @param psiClientKeyDescription   containing the information used to perform encryption operations (e.g. exponent of the private key)
     * @param psiCacheProvider          implementation of the psiCacheProvider
     * @return a PsiClient instance configured respect to the input parameters
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
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
