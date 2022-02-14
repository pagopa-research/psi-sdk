package psi.model;

import java.io.Serializable;

/**
 * This object can be used by the user to configure the number of thread used by the psi computation, and their max
 * lifetime. If these values are not specified by the user, default values are used.
 */
public class PsiRuntimeConfiguration implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer threads;

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
