package psi.server;

import psi.cache.EncryptionCacheProvider;
import psi.model.KeyDescription;
import psi.model.ServerSessionPayload;
import psi.utils.CustomTypeConverter;

public abstract class PsiAbstractServer implements PsiServer {

    protected static final int DEFAULT_THREADS = 4;
    protected static final int SESSION_DURATION_HOURS = 24;

    protected Long sessionId;
    protected int threads;
    protected ServerSessionPayload serverSessionPayload;
    protected EncryptionCacheProvider encryptionCacheProvider;

    public Long getSessionId() {
        return sessionId;
    }

    public void setSessionId(Long sessionId) {
        this.sessionId = sessionId;
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public KeyDescription getKeyDescription(){
        KeyDescription keyDescription = new KeyDescription();
        if(serverSessionPayload.getCacheKeyId() != null)
            keyDescription.setKeyId(serverSessionPayload.getCacheKeyId());
        keyDescription.setKey(CustomTypeConverter.convertBigIntegerToString(serverSessionPayload.getServerPrivateKey()));
        keyDescription.setModulus(CustomTypeConverter.convertBigIntegerToString(serverSessionPayload.getModulus()));
        return keyDescription;
    }

    @Override
    public ServerSessionPayload getSessionPayload() {
        return serverSessionPayload;
    }

    public void setSessionPayload(ServerSessionPayload serverSessionPayload) {
        this.serverSessionPayload = serverSessionPayload;
    }

    @Override
    public String toString() {
        return "PsiAbstractServer{" +
                "sessionId=" + sessionId +
                ", threads=" + threads +
                ", sessionPayload=" + serverSessionPayload +
                '}';
    }
}
