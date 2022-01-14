package psi.dto;

import java.time.Instant;

public class PsiSessionDTO {

    private Long sessionId;

    private String modulus;

    private String serverPublicKey;

    private PsiAlgorithmParameterDTO psiAlgorithmParameterDTO;

    public Long getSessionId() {
        return sessionId;
    }

    public void setSessionId(Long sessionId) {
        this.sessionId = sessionId;
    }

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
        return "SessionDTO{" +
                "sessionId=" + sessionId +
                ", modulus='" + modulus + '\'' +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", sessionParameterDTO=" + psiAlgorithmParameterDTO +
                '}';
    }
}
