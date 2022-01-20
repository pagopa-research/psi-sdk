package psi.server;

import psi.cache.PsiCacheProvider;
import psi.utils.StatisticsFactory;

import java.util.List;

public abstract class PsiAbstractServer implements PsiServer {

    protected static final int DEFAULT_THREADS = 4;
    protected int threads;

    protected PsiServerSession psiServerSession;
    protected PsiCacheProvider psiCacheProvider;

    protected Long keyId;

    protected List<StatisticsFactory> statisticList;

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public PsiServerSession getServerSession() {
        return psiServerSession;
    }

    public PsiCacheProvider getPsiCacheProvider() {
        return psiCacheProvider;
    }

    public List<StatisticsFactory> getStatisticList() {
        return statisticList;
    }

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }
}
