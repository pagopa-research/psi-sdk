package psi.client;

import psi.cache.PsiCacheProvider;
import psi.utils.PsiPhaseStatistics;

import java.util.Iterator;
import java.util.List;
import java.util.Queue;

public abstract class PsiAbstractClient implements PsiClient {

    protected static final int DEFAULT_THREADS = 4;
    protected static final int THREAD_MAX_SECONDS_LIFETIME = 10800;

    protected Integer threads;
    protected Boolean cacheEnabled;
    protected Long keyId;
    protected PsiCacheProvider psiCacheProvider;

    protected Queue<PsiPhaseStatistics> statisticList;

    public Integer getThreads() {
        return threads;
    }

    public void setThreads(Integer threads) {
        this.threads = threads;
    }

    public Boolean getCacheEnabled() {
        return cacheEnabled;
    }

    public Long getKeyId() {
        return keyId;
    }

    public PsiCacheProvider getPsiCacheProvider() {
        return psiCacheProvider;
    }

    public Iterator<PsiPhaseStatistics> getStatisticList() {
        return statisticList.iterator();
    }

    @Override
    public String toString() {
        return "PsiAbstractClient{" +
                ", threads=" + threads +
                ", cacheEnabled=" + cacheEnabled +
                ", keyId=" + keyId +
                ", psiCacheProvider=" + psiCacheProvider +
                '}';
    }
}
