package psi;

import psi.cache.PsiCacheProvider;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiRuntimeConfiguration;
import psi.server.PsiServer;

import java.util.List;

/**
 * Abstract representation of a PsiServer containing methods and variables shared by all the PsiServer implementations
 */
abstract class PsiServerAbstract implements PsiServer {

    private static final int DEFAULT_THREADS = 4;
    private static final int DEFAULT_THREAD_TIMEOUT_SECONDS = 10800;

    protected PsiServerSession psiServerSession;
    protected PsiCacheProvider psiCacheProvider;

    protected Long keyId;

    protected int threads = DEFAULT_THREADS;
    protected int threadTimeoutSeconds = DEFAULT_THREAD_TIMEOUT_SECONDS;

    protected List<PsiPhaseStatistics> statisticList;

    public int getThreads() {
        return threads;
    }

    public PsiServerSession getServerSession() {
        return psiServerSession;
    }

    public PsiCacheProvider getPsiCacheProvider() {
        return psiCacheProvider;
    }

    public List<PsiPhaseStatistics> getStatisticList() {
        return statisticList;
    }

    public void setConfiguration(PsiRuntimeConfiguration configuration){
        this.threads = configuration.getThreads() != null ?
                configuration.getThreads() : DEFAULT_THREADS;
        this.threadTimeoutSeconds = configuration.getThreadTimeoutSeconds() != null ?
                configuration.getThreadTimeoutSeconds() : DEFAULT_THREAD_TIMEOUT_SECONDS;
    }

    public Long getKeyId() {
        return keyId;
    }

    public void setKeyId(Long keyId) {
        this.keyId = keyId;
    }
}
