package psi.dto;

import java.time.Instant;

public class SessionDTO {

    private long sessionId;

    private Instant expiration;

    private String modulus;

    private String serverPublicKey;

    private SessionParameterDTO sessionParameterDTO;

    public long getSessionId() {
        return sessionId;
    }

    public void setSessionId(long sessionId) {
        this.sessionId = sessionId;
    }

    public Instant getExpiration() {
        return expiration;
    }

    public void setExpiration(Instant expiration) {
        this.expiration = expiration;
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

    public SessionParameterDTO getSessionParameterDTO() {
        return sessionParameterDTO;
    }

    public void setSessionParameterDTO(SessionParameterDTO sessionParameterDTO) {
        this.sessionParameterDTO = sessionParameterDTO;
    }

    @Override
    public String toString() {
        return "SessionDTO{" +
                "sessionId=" + sessionId +
                ", expiration=" + expiration +
                ", modulus='" + modulus + '\'' +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", sessionParameterDTO=" + sessionParameterDTO +
                '}';
    }
}
