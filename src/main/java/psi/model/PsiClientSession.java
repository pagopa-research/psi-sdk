package psi.model;

import psi.exception.CustomRuntimeException;
import psi.exception.PsiServerException;
import psi.server.PsiServerSession;
import psi.utils.CustomTypeConverter;

import java.util.Arrays;

public class PsiClientSession {

    private String modulus;

    private String serverPublicKey;

    private PsiAlgorithmParameter psiAlgorithmParameter;

    public String getModulus() {
        return modulus;
    }

    public void setModulus(String modulus) {
        this.modulus = modulus;
    }

    public String getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(String serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    public PsiAlgorithmParameter getPsiAlgorithmParameter() {
        return psiAlgorithmParameter;
    }

    public void setPsiAlgorithmParameter(PsiAlgorithmParameter psiAlgorithmParameter) {
        this.psiAlgorithmParameter = psiAlgorithmParameter;
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
        PsiAlgorithmParameter psiAlgorithmParameter = new PsiAlgorithmParameter();
        psiAlgorithmParameter.setAlgorithm((psiServerSession.getPsiAlgorithmParameter().getAlgorithm()));
        psiAlgorithmParameter.setKeySize(psiServerSession.getPsiAlgorithmParameter().getKeySize());
        psiClientSession.setPsiAlgorithmParameter(psiAlgorithmParameter);

        switch(psiServerSession.getPsiAlgorithmParameter().getAlgorithm()){
            case BS:
                if(psiServerSession.getPsiServerKeyDescription().getModulus() == null)
                    throw new PsiServerException("The field modulus of psiServerKeyDescription cannot be null");
                psiClientSession.setModulus(
                        CustomTypeConverter.convertBigIntegerToString(psiServerSession.getPsiServerKeyDescription().getModulus()));
                if(psiServerSession.getPsiServerKeyDescription().getPublicKey() == null)
                    throw new PsiServerException("The field publicKey of psiServerKeyDescription cannot be null");
                psiClientSession.setServerPublicKey(
                        CustomTypeConverter.convertBigIntegerToString(psiServerSession.getPsiServerKeyDescription().getPublicKey()));
                break;
            case DH:
                if(psiServerSession.getPsiServerKeyDescription().getModulus() == null)
                    throw new PsiServerException("The field modulus of psiServerKeyDescription cannot be null");
                psiClientSession.setModulus(
                        CustomTypeConverter.convertBigIntegerToString(psiServerSession.getPsiServerKeyDescription().getModulus()));
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
