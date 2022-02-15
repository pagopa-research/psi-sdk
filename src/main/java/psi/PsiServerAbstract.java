package psi;

import psi.cache.PsiCacheProvider;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiRuntimeConfiguration;
import psi.server.PsiServer;

import java.util.List;

import static psi.GlobalVariables.DEFAULT_THREADS;
import static psi.GlobalVariables.DEFAULT_THREAD_TIMEOUT_SECONDS;

/**
 * Abstract representation of a PsiServer containing variables common to all the psiClient implementation,
 */
abstract class PsiServerAbstract implements PsiServer {

    protected PsiServerSession psiServerSession;

    // Identifier of the current key, used to store and retrieve values to/from the cache
    protected Long keyId;

    protected PsiCacheProvider psiCacheProvider;

    protected int threads = DEFAULT_THREADS;
    protected int threadTimeoutSeconds = DEFAULT_THREAD_TIMEOUT_SECONDS;

    protected List<PsiPhaseStatistics> statisticList;

    public int getThreads() {
        return this.threads;
    }

    public PsiServerSession getServerSession() {
        return this.psiServerSession;
    }

    public PsiCacheProvider getPsiCacheProvider() {
        return this.psiCacheProvider;
    }

    public List<PsiPhaseStatistics> getStatisticList() {
        return this.statisticList;
    }

    public void setConfiguration(PsiRuntimeConfiguration configuration){
        this.threads = configuration.getThreads() != null ?
                configuration.getThreads() : DEFAULT_THREADS;
        this.threadTimeoutSeconds = configuration.getThreadTimeoutSeconds() != null ?
                configuration.getThreadTimeoutSeconds() : DEFAULT_THREAD_TIMEOUT_SECONDS;
    }
}
