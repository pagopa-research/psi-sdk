package psi.dto;

public class PsiSessionDTO {

    private String modulus;

    private String serverPublicKey;

    private PsiAlgorithmParameterDTO psiAlgorithmParameterDTO;

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

    public PsiAlgorithmParameterDTO getSessionParameterDTO() {
        return psiAlgorithmParameterDTO;
    }

    public void setSessionParameterDTO(PsiAlgorithmParameterDTO psiAlgorithmParameterDTO) {
        this.psiAlgorithmParameterDTO = psiAlgorithmParameterDTO;
    }

    @Override
    public String toString() {
        return "PsiSessionDTO{" +
                "modulus='" + modulus + '\'' +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", psiAlgorithmParameterDTO=" + psiAlgorithmParameterDTO +
                '}';
    }
}
