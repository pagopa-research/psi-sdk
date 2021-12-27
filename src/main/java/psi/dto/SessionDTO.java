package psi.dto;

import java.sql.Timestamp;

public class SessionDTO {

    private long sessionId;

    private Timestamp expiration;

    private String modulus;

    private String serverPublicKey;

    private SessionParameterDTO sessionParameterDTO;

    public long getSessionId() {
        return sessionId;
    }

    public void setSessionId(long sessionId) {
        this.sessionId = sessionId;
    }

    public Timestamp getExpiration() {
        return expiration;
    }

    public void setExpiration(Timestamp expiration) {
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
