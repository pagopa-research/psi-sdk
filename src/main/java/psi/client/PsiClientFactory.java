package psi.client;

import psi.cache.PsiCacheProvider;
import psi.client.algorithm.bs.BsPsiClient;
import psi.client.algorithm.bs.model.BsClientKeyDescription;
import psi.client.model.PsiClientKeyDescription;
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
        if(psiSessionDTO.getSessionId() == null || psiSessionDTO.getSessionId() <= 0)
            throw new PsiClientException("The id of the input sessionDTO is invalid");

        if(!Arrays.asList(supportedAlgorithms).contains(psiSessionDTO.getSessionParameterDTO().getAlgorithm()))
            throw new PsiClientException("The algorithm defined in the input sessionDTO is invalid or not supported");

        switch(psiSessionDTO.getSessionParameterDTO().getAlgorithm()){
            case "BS":
                if(psiClientKeyDescription != null && !(psiClientKeyDescription instanceof BsClientKeyDescription))
                    throw new PsiClientException("The subclass of the input clientKeyDescription does not match the algorithm. Should pass as clientKeyDescription an instance of BsClientKeyDescription.");
                return new BsPsiClient(psiSessionDTO, psiClientKeyDescription != null ? (BsClientKeyDescription) psiClientKeyDescription : null, psiCacheProvider);
            case "DH":

            default:
                return null;
        }
    }
}