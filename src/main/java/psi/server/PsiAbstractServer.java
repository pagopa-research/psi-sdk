package psi.server;

import psi.cache.PsiCacheProvider;
import psi.server.model.ServerSession;

public abstract class PsiAbstractServer implements PsiServer {

    protected static final int DEFAULT_THREADS = 4;
    protected int threads;

    protected ServerSession serverSession;
    protected PsiCacheProvider psiCacheProvider;

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public ServerSession getServerSession() {
        return serverSession;
    }

    public PsiCacheProvider getPsiCacheProvider() {
        return psiCacheProvider;
    }
}
