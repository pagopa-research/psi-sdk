package psi.client;

import psi.cache.PsiCacheProvider;

import java.math.BigInteger;
import java.util.Set;

public abstract class PsiAbstractClient implements PsiClient {

    protected static final int DEFAULT_THREADS = 4;

    protected Long sessionId;
    protected Integer threads;
    protected Set<BigInteger> serverEncryptedDataset;
    protected Boolean cacheEnabled;
    protected Long keyId;
    protected PsiCacheProvider encryptionCacheProvider;

    public Integer getThreads() {
        return threads;
    }

    public void setThreads(Integer threads) {
        this.threads = threads;
    }

    public Long getSessionId() {
        return sessionId;
    }

    public void setSessionId(Long sessionId) {
        this.sessionId = sessionId;
    }

    public Set<BigInteger> getServerEncryptedDataset() {
        return serverEncryptedDataset;
    }

    public Boolean getCacheEnabled() {
        return cacheEnabled;
    }

    public Long getKeyId() {
        return keyId;
    }

    public PsiCacheProvider getEncryptionCacheProvider() {
        return encryptionCacheProvider;
    }

    @Override
    public String toString() {
        return "PsiAbstractClient{" +
                "sessionId=" + sessionId +
                ", threads=" + threads +
                ", serverEncryptedDataset=" + serverEncryptedDataset +
                ", cacheEnabled=" + cacheEnabled +
                ", keyId=" + keyId +
                ", encryptionCacheProvider=" + encryptionCacheProvider +
                '}';
    }
}
