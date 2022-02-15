package psi;

import psi.cache.PsiCacheProvider;
import psi.client.PsiClient;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiRuntimeConfiguration;

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicLong;

import static psi.GlobalVariables.DEFAULT_THREADS;
import static psi.GlobalVariables.DEFAULT_THREAD_TIMEOUT_SECONDS;

/**
 * Abstract representation of a PsiClient containing variables common to all the psiClient implementation,
 */
abstract class PsiClientAbstract implements PsiClient {
    // Atomic counter used to uniquely identify client elements
    AtomicLong keyAtomicCounter;

    // Identifier of the current key, used to store and retrieve values to/from the cache
    protected Long keyId;

    Boolean cacheEnabled;

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
