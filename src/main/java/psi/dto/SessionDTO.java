package psi.dto;

import java.time.Instant;

public class SessionDTO {

    private Long sessionId;

    private Instant expiration;

    private String modulus;

    private String serverPublicKey;

    private SessionParameterDTO sessionParameterDTO;

    private Boolean cacheEnabled;

    public Long getSessionId() {
        return sessionId;
    }

    public void setSessionId(Long sessionId) {
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

    public Boolean getCacheEnabled() {
        return cacheEnabled;
    }

    public void setCacheEnabled(Boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }

    @Override
    public String toString() {
        return "SessionDTO{" +
                "sessionId=" + sessionId +
                ", expiration=" + expiration +
                ", modulus='" + modulus + '\'' +
                ", serverPublicKey='" + serverPublicKey + '\'' +
                ", sessionParameterDTO=" + sessionParameterDTO +
                ", cacheEnabled=" + cacheEnabled +
                '}';
    }
}
