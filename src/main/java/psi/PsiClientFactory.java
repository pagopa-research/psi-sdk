package psi;

import psi.cache.PsiCacheProvider;
import psi.client.PsiClient;
import psi.exception.PsiClientException;
import psi.exception.UnsupportedKeySizeException;
import psi.model.PsiAlgorithm;
import psi.model.PsiClientSession;

import java.util.Arrays;

/**
 * Offers a generic interface to load a specific PsiClient implementation and configuration
 * based on the provided inputs (client session, key description and cache provider).
 */
public class PsiClientFactory {

    private PsiClientFactory() {}

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession.
     * Any key, if needed, is generated automatically.
     * Methods of the returned object do not use the cache.
     *
     * @param psiClientSession contains the information sent from the server to correctly initialize the client
     * @return a PsiClient instance compliant with the input parameter
     * @throws UnsupportedKeySizeException if the specified key size is not supported by the selected algorithm
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession) throws UnsupportedKeySizeException {
        return loadSessionInner(psiClientSession, null, null);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession and
     * the provided psiClientKeyDescription.
     * The returned PsiClient uses the keys passed in the psiClientKeyDescription.
     * Methods of the returned object do not use the cache.
     *
     * @param psiClientSession          contains the information sent from the server to correctly initialize the client
     * @param psiClientKeyDescription   contains the key used to perform encryption operations (e.g. exponent of the private key)
     * @return a PsiClient instance compliant with the input parameter
     * @throws UnsupportedKeySizeException if the specified key size is not supported by the selected algorithm
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription) throws UnsupportedKeySizeException {
        if (psiClientKeyDescription == null) {
            throw new PsiClientException("Input clientKeyDescription is null");
        }

        return loadSessionInner(psiClientSession, psiClientKeyDescription, null);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession and the
     * input PsiCacheProvider implementation.
     * Any key, if needed, is generated automatically.
     * Methods of the returned object use the cache whenever possible.
     *
     * @param psiClientSession  contains the information sent from the server to correctly initialize the client
     * @param psiCacheProvider  custom implementation of the PsiCacheProvider
     * @return a PsiClient instance compliant with the input parameter
     * @throws UnsupportedKeySizeException if the specified key size is not supported by the selected algorithm
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiClientSession, null, psiCacheProvider);
    }

    /**
     * Creates the specific client object based on the algorithm field defined in the input psiClientSession,
     * the provided psiClientKeyDescription and the input PsiCacheProvider implementation.
     * The returned PsiClient uses the keys passed in the psiClientKeyDescription.
     * Methods of the returned object use the cache whenever possible.
     *
     * @param psiClientSession          contains the information sent from the server to correctly initialize the client
     * @param psiClientKeyDescription   contains the key used to perform encryption operations (e.g. exponent of the private key)
     * @param psiCacheProvider          custom implementation of the PsiCacheProvider
     * @return a PsiClient instance configured respect to the input parameters
     * @throws UnsupportedKeySizeException if the specified key size is not supported by the selected algorithm
     */
    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiClientKeyDescription == null)
            throw new PsiClientException("Input clientKeyDescription is null");

        if (psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiClientSession, psiClientKeyDescription, psiCacheProvider);
    }

    /**
     * Inner method used to create the actual PsiClient. It is hidden from the sdk users, and it
     * is called by the loadSession methods to select the algorithm-specific PsiClient sub-class.
     *
     * @param psiClientSession          contains the information sent from the server to correctly initialize the client
     * @param psiClientKeyDescription   contains the key used to perform encryption operations (e.g. exponent of the private key)
     * @param psiCacheProvider          custom implementation of the PsiCacheProvider
     * @return a PsiClient instance configured respect to the input parameters
     * @throws UnsupportedKeySizeException if the specified key size is not supported by the selected algorithm
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
