package psi.model;

import java.io.Serializable;

/**
 * Configuration object that can be used to configure the number of threads and max thread lifetime for PSI
 * calculations.
 */
public class PsiThreadConfiguration implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer threads;

    private Integer threadTimeoutSeconds = null;

    public PsiThreadConfiguration(Integer threads) {
        this.threads = threads;
    }

    public PsiThreadConfiguration(Integer threads, Integer threadTimeoutSeconds) {
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
