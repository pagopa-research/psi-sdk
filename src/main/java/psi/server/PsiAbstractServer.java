package psi.server;

import psi.cache.EncryptionCacheProvider;
import psi.model.KeyDescription;
import psi.model.BsServerSession;
import psi.model.ServerSession;
import psi.utils.CustomTypeConverter;

public abstract class PsiAbstractServer implements PsiServer {

    protected static final int DEFAULT_THREADS = 4;
    protected int threads;

    protected ServerSession serverSession;
    protected EncryptionCacheProvider encryptionCacheProvider;

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public ServerSession getServerSession() {
        return serverSession;
    }

    public EncryptionCacheProvider getEncryptionCacheProvider() {
        return encryptionCacheProvider;
    }
}
