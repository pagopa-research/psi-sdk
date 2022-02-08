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

    private String serverPublicKey;

    private String generator;

    private String ecSpecName;

    private String ecServerPublicKey;

    private PsiAlgorithmParameter psiAlgorithmParameter;

    public String getModulus() {
        return modulus;
    }

    public String getServerPublicKey() {
        return serverPublicKey;
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
        switch(psiServerSession.getPsiAlgorithmParameter().getAlgorithm()){
            case BS:
                if(psiServerKeyDesc.getModulus() == null || psiServerKeyDesc.getPublicKey() == null)
                    throw new PsiServerException("The fields modulus and publicKey of psiServerKeyDescription cannot be null for the BS algorithm");
                psiClientSession.modulus = psiServerKeyDesc.getModulus();
                psiClientSession.serverPublicKey = psiServerKeyDesc.getPublicKey();
                break;
            case DH:
                if(psiServerKeyDesc.getModulus() == null)
                    throw new PsiServerException("The field modulus of psiServerKeyDescription cannot be null for the DH algorithm");
                psiClientSession.modulus = psiServerKeyDesc.getModulus();
                psiClientSession.generator = psiServerKeyDesc.getGenerator();
                break;
            case ECBS:
                if(psiServerKeyDesc.getEcPublicKey() == null || psiServerKeyDesc.getEcSpecName() == null )
                    throw new PsiServerException("The fields ecSpecName and ecPublicKey of psiServerKeyDescription cannot be null for the ECBS algorithm");
                psiClientSession.ecServerPublicKey = psiServerKeyDesc.getEcPublicKey();
                psiClientSession.ecSpecName = psiServerKeyDesc.getEcSpecName();
                break;
            case ECDH:
                if(psiServerKeyDesc.getEcSpecName() == null )
                    throw new PsiServerException("The fields ecSpecName of psiServerKeyDescription cannot be null for the ECDH algorithm");
                psiClientSession.ecSpecName = psiServerKeyDesc.getEcSpecName();
                break;
            default:
                throw new PsiServerException("The algorithm in psiServerSession is unsupported or invalid");
        }

        return psiClientSession;
    }

    public String getEcSpecName() {
        return ecSpecName;
    }

    public String getEcServerPublicKey() {
        return ecServerPublicKey;
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
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", generator='" + generator + '\'' +
                ", ecSpecName='" + ecSpecName + '\'' +
                ", ecServerPublicKey='" + ecServerPublicKey + '\'' +
                ", psiAlgorithmParameter=" + psiAlgorithmParameter +
                '}';
    }
}
