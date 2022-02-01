package psi.model;

import psi.exception.CustomRuntimeException;
import psi.exception.PsiServerException;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerSession;
import psi.utils.CustomTypeConverter;

import java.util.Arrays;

public class PsiClientSession {

    private String modulus;

    private String serverPublicKey;

    private String ecSpecName;

    private String ecServerPublicKey;

    private PsiAlgorithmParameter psiAlgorithmParameter;

    public String getModulus() {
        return modulus;
    }

    public String getServerPublicKey() {
        return serverPublicKey;
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
                psiClientSession.modulus = (CustomTypeConverter.convertBigIntegerToString(psiServerKeyDesc.getModulus()));
                psiClientSession.serverPublicKey = (CustomTypeConverter.convertBigIntegerToString(psiServerKeyDesc.getPublicKey()));
                break;
            case DH:
                if(psiServerKeyDesc.getModulus() == null)
                    throw new PsiServerException("The field modulus of psiServerKeyDescription cannot be null for the DH algorithm");
                psiClientSession.modulus = (CustomTypeConverter.convertBigIntegerToString(psiServerKeyDesc.getModulus()));
                break;
            case ECBS:
                if(psiServerKeyDesc.getEcPublicKey() == null || psiServerKeyDesc.getEcSpec() == null )
                    throw new PsiServerException("The fields ecSpec and ecPublicKey of psiServerKeyDescription cannot be null for the ECBS algorithm");
                psiClientSession.ecServerPublicKey = CustomTypeConverter.convertECPointToString(psiServerKeyDesc.getEcPublicKey());
                psiClientSession.ecSpecName = CustomTypeConverter.convertECParameterSpecToString(psiServerKeyDesc.getEcSpec());

                break;

            default:
                throw new PsiServerException("The algorithm in psiServerSession is unsupported or invalid");
        }

        return psiClientSession;
    }

    @Override
    public String toString() {
        return "PsiClientSession{" +
                "modulus='" + modulus + '\'' +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", psiAlgorithmParameter=" + psiAlgorithmParameter +
                '}';
    }
}
