package psi.client;

import psi.cache.PsiCacheProvider;
import psi.client.algorithm.bs.BsPsiClient;
import psi.client.algorithm.dh.DhPsiClient;
import psi.model.PsiClientSession;
import psi.exception.PsiClientException;
import psi.model.PsiAlgorithm;

import java.util.Arrays;

public class PsiClientFactory {

    private PsiClientFactory() {}

    /**  Creates the specific client object based on the algorithm field defined in the input psiClientSession */
    public static PsiClient loadSession(PsiClientSession psiClientSession){
       return loadSessionInner(psiClientSession, null, null);
    }

    /**  Creates the specific client object based on the algorithm field defined in the input psiClientSession */
    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription){
        if(psiClientKeyDescription == null){
            throw new PsiClientException("Input clientKeyDescription is null");
        }

        return loadSessionInner(psiClientSession, psiClientKeyDescription, null);
    }

    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiCacheProvider psiCacheProvider){
        if(psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiClientSession, null, psiCacheProvider);
    }

    public static PsiClient loadSession(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider){
        if(psiClientKeyDescription == null)
            throw new PsiClientException("Input clientKeyDescription is null");

        if(psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiClientSession, psiClientKeyDescription, psiCacheProvider);
    }

    /**  Creates the specific client object based on the algorithm field defined in the input psiClientSession */
    private static PsiClient loadSessionInner(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider){
        if(!Arrays.asList(PsiAlgorithm.values()).contains(psiClientSession.getPsiAlgorithmParameter().getAlgorithm()))
            throw new PsiClientException("The algorithm defined in the input psiClientSession is invalid or not supported");

        switch(psiClientSession.getPsiAlgorithmParameter().getAlgorithm()){
            case BS:
                return new BsPsiClient(psiClientSession, psiClientKeyDescription, psiCacheProvider);
            case DH:
                return new DhPsiClient(psiClientSession, psiClientKeyDescription, psiCacheProvider);

            default:
                return null;
        }
    }
}
