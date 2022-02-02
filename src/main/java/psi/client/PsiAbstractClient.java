package psi.client;

import psi.cache.PsiCacheProvider;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiRuntimeConfiguration;

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;

public abstract class PsiAbstractClient implements PsiClient {

    private static final int DEFAULT_THREADS = 4;
    private static final int DEFAULT_THREAD_TIMEOUT_SECONDS = 10800;

    protected Boolean cacheEnabled;
    protected Long keyId;
    protected PsiCacheProvider psiCacheProvider;

    protected int threads = DEFAULT_THREADS;
    protected int threadTimeoutSeconds = DEFAULT_THREAD_TIMEOUT_SECONDS;

    protected Queue<PsiPhaseStatistics> statisticList;

    public Integer getThreads() {
        return threads;
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

    public void setConfiguration(PsiRuntimeConfiguration configuration){
        this.threads = configuration.getThreads() != null ?
                configuration.getThreads() : DEFAULT_THREADS;
        this.threadTimeoutSeconds = configuration.getThreadTimeoutSeconds() != null ?
                configuration.getThreadTimeoutSeconds() : DEFAULT_THREAD_TIMEOUT_SECONDS;
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
