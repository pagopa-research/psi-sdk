package psi.model;

import psi.PsiServerSession;
import psi.exception.CustomRuntimeException;
import psi.exception.PsiServerException;
import psi.server.PsiServerKeyDescription;

import java.io.Serializable;
import java.util.Arrays;

public class PsiClientSession implements Serializable {

    private static final long serialVersionUID = 1L;

    private String modulus;

    private String serverPublicExponent;

    private String generator;

    private String ecServerPublicQ;

    private PsiAlgorithmParameter psiAlgorithmParameter;

    public String getModulus() {
        return modulus;
    }

    public static PsiClientSession getFromServerSession(PsiServerSession psiServerSession){
        if(psiServerSession == null || psiServerSession.getCacheEnabled() == null
                || psiServerSession.getPsiAlgorithmParameter() == null
                || psiServerSession.getPsiAlgorithmParameter().getAlgorithm() == null
                || psiServerSession.getPsiAlgorithmParameter().getKeySize() == null)
            throw new PsiServerException("The fields algorithm, keySize and cacheEnabled of psiServerSession cannot be null");

        if(psiServerSession.getPsiServerKeyDescription() == null)
            throw new CustomRuntimeException("The PsiServerKeyDescription of the psiServerSession cannot be null");

        if(!Arrays.asList(PsiAlgorithm.values()).contains(psiServerSession.getPsiAlgorithmParameter().getAlgorithm()))
            throw new PsiServerException("The algorithm in psiServerSession is unsupported or invalid");

        PsiClientSession psiClientSession = new PsiClientSession();
        psiClientSession.psiAlgorithmParameter = new PsiAlgorithmParameter();
        psiClientSession.psiAlgorithmParameter.setAlgorithm((psiServerSession.getPsiAlgorithmParameter().getAlgorithm()));
        psiClientSession.psiAlgorithmParameter.setKeySize(psiServerSession.getPsiAlgorithmParameter().getKeySize());

        PsiServerKeyDescription psiServerKeyDesc = psiServerSession.getPsiServerKeyDescription();
        switch(psiServerSession.getPsiAlgorithmParameter().getAlgorithm()) {
            case BS:
                if (psiServerKeyDesc.getModulus() == null || psiServerKeyDesc.getPublicExponent() == null)
                    throw new PsiServerException("The fields modulus and publicExponent of psiServerKeyDescription cannot be null for the BS algorithm");
                psiClientSession.modulus = psiServerKeyDesc.getModulus();
                psiClientSession.serverPublicExponent = psiServerKeyDesc.getPublicExponent();
                break;
            case DH:
                if (psiServerKeyDesc.getModulus() == null || psiServerKeyDesc.getGenerator() == null)
                    throw new PsiServerException("The fields modulus and generator of psiServerKeyDescription cannot be null for the DH algorithm");
                psiClientSession.modulus = psiServerKeyDesc.getModulus();
                psiClientSession.generator = psiServerKeyDesc.getGenerator();
                break;
            case ECBS:
                if (psiServerKeyDesc.getEcPublicQ() == null)
                    throw new PsiServerException("The field ecPublicQ of psiServerKeyDescription cannot be null for the ECBS algorithm");
                psiClientSession.ecServerPublicQ = psiServerKeyDesc.getEcPublicQ();
                break;
            case ECDH:
                break;
            default:
                throw new PsiServerException("The algorithm in psiServerSession is unsupported or invalid");
        }

        return psiClientSession;
    }

    public String getServerPublicExponent() {
        return serverPublicExponent;
    }

    public String getEcServerPublicQ() {
        return ecServerPublicQ;
    }

    public PsiAlgorithmParameter getPsiAlgorithmParameter() {
        return psiAlgorithmParameter;
    }

    public String getGenerator() {
        return generator;
    }

    @Override
    public String toString() {
        return "PsiClientSession{" +
                "modulus='" + modulus + '\'' +
                ", serverPublicExponent='" + serverPublicExponent + '\'' +
                ", generator='" + generator + '\'' +
                ", ecServerPublicQ='" + ecServerPublicQ + '\'' +
                ", psiAlgorithmParameter=" + psiAlgorithmParameter +
                '}';
    }
}
