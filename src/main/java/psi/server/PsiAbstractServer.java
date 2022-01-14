package psi.server;

import psi.cache.PsiCacheProvider;
import psi.model.ServerSession;
import psi.utils.StatisticsFactory;

import java.util.List;

public abstract class PsiAbstractServer implements PsiServer {

    protected static final int DEFAULT_THREADS = 4;
    protected int threads;

    protected ServerSession serverSession;
    protected PsiCacheProvider encryptionCacheProvider;

    protected List<StatisticsFactory> statisticList;

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public ServerSession getServerSession() {
        return serverSession;
    }

    public PsiCacheProvider getEncryptionCacheProvider() {
        return encryptionCacheProvider;
    }

    public List<StatisticsFactory> getStatisticList() {
        return statisticList;
    }
}
