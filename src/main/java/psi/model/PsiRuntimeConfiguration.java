package psi.model;

import java.io.Serializable;

public class PsiRuntimeConfiguration implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer threads = null;

    private Integer threadTimeoutSeconds = null;

    public PsiRuntimeConfiguration(Integer threads) {
        this.threads = threads;
    }

    public PsiRuntimeConfiguration(Integer threads, Integer threadTimeoutSeconds) {
        this.threads = threads;
        this.threadTimeoutSeconds = threadTimeoutSeconds;
    }

    public Integer getThreads() {
        return threads;
    }

    public void setThreads(Integer threads) {
        this.threads = threads;
    }

    public Integer getThreadTimeoutSeconds() {
        return threadTimeoutSeconds;
    }

    public void setThreadTimeoutSeconds(Integer threadTimeoutSeconds) {
        this.threadTimeoutSeconds = threadTimeoutSeconds;
    }
}
