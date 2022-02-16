package psi;

import psi.cache.PsiCacheProvider;
import psi.exception.PsiServerException;
import psi.exception.PsiServerInitException;
import psi.exception.UnsupportedKeySizeException;
import psi.exception.UnsupportedKeySizeRuntimeException;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.server.PsiServer;

import java.util.Arrays;

/**
 * Offers a generic interface to initialize or load a specific PsiServer implementation and
 * configuration depending on the provided inputs (algorithm parameters, key description and cache provider).
 */
public class PsiServerFactory {

    private PsiServerFactory() {}

    /**
     * Initialize a new server session based on the input PsiAlgorithmParameter.
     * The keys of the returned PsiServerSession are generated automatically. Methods of the returned object
     * do not use the cache.
     *
     * @param psiAlgorithmParameter contains the algorithm and the key size selected by the client
     * @return a ServerSession which is an instance of the PsiServer subclass that matches the algorithm defined
     * in the PsiAlgorithmParameter
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
     */
    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter) throws UnsupportedKeySizeException {
        return initSessionInner(psiAlgorithmParameter, null, null);
    }

    /**
     * Initialize a new server session based on the input PsiAlgorithmParameter and the input PsiServerKeyDescription.
     * The returned PsiServerSession uses the keys passed in PsiServerKeyDescription.
     * Methods of the returned object do not use the cache.
     *
     * @param psiAlgorithmParameter     contains the algorithm and the key size selected by the client
     * @param psiServerKeyDescription   contains the keys used to perform encryption operations (e.g. exponent of the private key)
     * @return a ServerSession which is an instance of the PsiServer subclass that matches the algorithm defined
     * in the PsiAlgorithmParameter
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
     */
    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription) throws UnsupportedKeySizeException {
        if (psiServerKeyDescription == null) {
            throw new PsiServerInitException("Input serverKeyDescription is null");
        }

        return initSessionInner(psiAlgorithmParameter, psiServerKeyDescription, null);
    }

    /**
     * Initialize a new server session based on the input PsiAlgorithmParameter and the passed PsiCacheProvider implementation.
     * The keys of the returned PsiServerSession are generated automatically.
     * Methods of the returned object use the cache whenever possible.
     *
     * @param psiAlgorithmParameter contains the algorithm and the key size selected by the client
     * @param psiCacheProvider      implementation of the psiCacheProvider
     * @return a ServerSession which is an instance of the PsiServer subclass that matches the algorithm defined
     * in the PsiAlgorithmParameter
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
     */
    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        return initSessionInner(psiAlgorithmParameter, null, psiCacheProvider);
    }

    /**
     * Initialize a new server session based on the input PsiAlgorithmParameter, the input PsiServerKeyDescription and the
     * passed PsiCacheProvider implementation.
     * The returned PsiServerSession uses the keys passed in PsiServerKeyDescription.
     * Methods of the returned object use the cache whenever possible.
     *
     * @param psiAlgorithmParameter     contains the algorithm and the key size selected by the client
     * @param psiServerKeyDescription   contains the keys used to perform encryption operations (e.g. exponent of the private key)
     * @param psiCacheProvider          implementation of the psiCacheProvider
     * @return a ServerSession which is an instance of the PsiServer subclass that matches the algorithm defined
     * in the PsiAlgorithmParameter
     * @throws UnsupportedKeySizeException if the specified key size is not supported for the selected algorithm
     */
    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiServerKeyDescription == null) {
            throw new PsiServerInitException("Input serverKeyDescription is null");
        }

        return initSessionInner(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);
    }

    /**
     * Calls the static method of the specific PsiServer subclass matching the algorithm set in the
     * PsiAlgorithmParameter.
     *
     * @param psiAlgorithmParameter   contains the algorithm and the key size selected by the client
     * @param psiServerKeyDescription if not null, the algorithm uses the input keys. If null, creates a new key
     * @param psiCacheProvider        if not null, uses this object as a cache provider. If null, no cache is used
     * @return a ServerSession which is an instance of the PsiServer subclass that matches the algorithm defined
     * in the PsiAlgorithmParameter
     */
    private static PsiServerSession initSessionInner(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (psiAlgorithmParameter == null || psiAlgorithmParameter.getAlgorithm() == null || psiAlgorithmParameter.getKeySize() == null)
            throw new PsiServerInitException("Input psiAlgorithmParameter or its fields are null");

        if (!Arrays.asList(PsiAlgorithm.values()).contains(psiAlgorithmParameter.getAlgorithm()))
            throw new PsiServerInitException("The algorithm defined in the input psiAlgorithmParameter is invalid or not supported");

        if (!psiAlgorithmParameter.getAlgorithm().getSupportedKeySize().contains(psiAlgorithmParameter.getKeySize()))
            throw new UnsupportedKeySizeException(psiAlgorithmParameter.getAlgorithm(), psiAlgorithmParameter.getKeySize());

        switch (psiAlgorithmParameter.getAlgorithm()) {
            case BS:
                return PsiServerBs.initSession(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);
            case DH:
                return PsiServerDh.initSession(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);
            case ECBS:
                return PsiServerEcBs.initSession(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);
            case ECDH:
                return PsiServerEcDh.initSession(psiAlgorithmParameter, psiServerKeyDescription, psiCacheProvider);

            default:
                return null;
        }
    }

    /**
     * Creates a PsiServer, selecting the relative implementation based on the input algorithm. The PsiServer is
     * initialized with the information contained in the input PsiServerSession object.
     *
     * @param psiServerSession contains all the information required to build a PsiServer
     * @return a PsiServer instance that matches the algorithm defined in the PsiAlgorithmParameter
     */
    public static PsiServer loadSession(PsiServerSession psiServerSession) {
        return loadSession(psiServerSession, null);
    }

    /**
     * Create a PsiServer, selecting the relative implementation based on the input algorithm. The PsiServer is
     * initialized with the information contained into the PsiServerSession object.
     *
     * @param psiServerSession contains all the information required to build a PsiServer
     * @param psiCacheProvider if not null, uses this object as a cache provider
     * @return a PsiServer instance that matches the algorithm defined in the PsiAlgorithmParameter
     */
    public static PsiServer loadSession(PsiServerSession psiServerSession, PsiCacheProvider psiCacheProvider) {
        if (psiServerSession == null || psiServerSession.getCacheEnabled() == null
                || psiServerSession.getPsiAlgorithmParameter() == null
                || psiServerSession.getPsiAlgorithmParameter().getAlgorithm() == null
                || psiServerSession.getPsiAlgorithmParameter().getKeySize() == null)
            throw new PsiServerInitException("The fields cacheEnabled, algorithm and keySize of the input psiServerSession cannot be null");

        if (Boolean.TRUE.equals(psiServerSession.getCacheEnabled()) && psiCacheProvider == null)
            throw new PsiServerException("The session has the cache enabled but you didn't pass an implementation of psiCacheProvider as parameter of loadSession()");

        if (Boolean.TRUE.equals(!psiServerSession.getCacheEnabled()) && psiCacheProvider != null)
            throw new PsiServerException("The session has the cache disabled but you still passed an implementation of psiCacheProvider as parameter of loadSession()");

        if (!psiServerSession.getPsiAlgorithmParameter().getAlgorithm().getSupportedKeySize().contains(psiServerSession.getPsiAlgorithmParameter().getKeySize()))
            throw new UnsupportedKeySizeRuntimeException(psiServerSession.getPsiAlgorithmParameter().getAlgorithm(), psiServerSession.getPsiAlgorithmParameter().getKeySize());

        switch (psiServerSession.getPsiAlgorithmParameter().getAlgorithm()) {
            case BS:
                return new PsiServerBs(psiServerSession, psiCacheProvider);

            case DH:
                return new PsiServerDh(psiServerSession, psiCacheProvider);

            case ECBS:
                return new PsiServerEcBs(psiServerSession, psiCacheProvider);

            case ECDH:
                return new PsiServerEcDh(psiServerSession, psiCacheProvider);

            default:
                return null;
        }
    }


}
