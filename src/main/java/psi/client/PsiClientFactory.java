package psi.client;

import psi.cache.PsiCacheProvider;
import psi.client.algorithm.bs.BsPsiClient;
import psi.dto.PsiSessionDTO;
import psi.exception.PsiClientException;

import java.util.Arrays;

public class PsiClientFactory {

    static String[] supportedAlgorithms =
        {
                "BS",
                "ECBS",
                "DH",
                "ECDH"
        };

    /**  Creates the specific client object based on the algorithm field defined in the input sessionDTO */
    public static PsiClient loadSession(PsiSessionDTO psiSessionDTO){
       return loadSessionInner(psiSessionDTO, null, null);
    }

    /**  Creates the specific client object based on the algorithm field defined in the input sessionDTO */
    public static PsiClient loadSession(PsiSessionDTO psiSessionDTO, PsiClientKeyDescription psiClientKeyDescription){
        if(psiClientKeyDescription == null){
            throw new PsiClientException("Input clientKeyDescription is null");
        }

        return loadSessionInner(psiSessionDTO, psiClientKeyDescription, null);
    }

    public static PsiClient loadSession(PsiSessionDTO psiSessionDTO, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider){
        if(psiClientKeyDescription == null)
            throw new PsiClientException("Input clientKeyDescription is null");

        if(psiCacheProvider == null)
            throw new PsiClientException("Input psiCacheProvider is null");

        return loadSessionInner(psiSessionDTO, psiClientKeyDescription, psiCacheProvider);
    }

    /**  Creates the specific client object based on the algorithm field defined in the input sessionDTO */
    private static PsiClient loadSessionInner(PsiSessionDTO psiSessionDTO, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider){
        if(!Arrays.asList(supportedAlgorithms).contains(psiSessionDTO.getPsiAlgorithmParameterDTO().getAlgorithm().toString()))
            throw new PsiClientException("The algorithm defined in the input sessionDTO is invalid or not supported");

        switch(psiSessionDTO.getPsiAlgorithmParameterDTO().getAlgorithm()){
            case BS:
                return new BsPsiClient(psiSessionDTO, psiClientKeyDescription, psiCacheProvider);
            case DH:

            default:
                return null;
        }
    }
}
