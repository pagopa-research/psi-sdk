package psi.client;

import psi.cache.PsiCacheProvider;
import psi.utils.PsiPhaseStatistics;

import java.util.*;

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

    public List<PsiPhaseStatistics> getStatisticList() {
        List<PsiPhaseStatistics> psiPhaseStatisticsList = new ArrayList<>(statisticList.size());
        statisticList.iterator().forEachRemaining(elem -> psiPhaseStatisticsList.add(0, elem));
        return psiPhaseStatisticsList;
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
