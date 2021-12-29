package psi.server;

import psi.server.model.SessionPayload;

public abstract class PsiAbstractServer implements PsiServer {

    protected static final int DEFAULT_THREADS = 4;
    protected static final int SESSION_DURATION_HOURS = 24;

    protected Long sessionId;
    protected int threads;
    protected SessionPayload sessionPayload;

    public Long getSessionId() {
        return sessionId;
    }

    public void setSessionId(Long sessionId) {
        this.sessionId = sessionId;
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    @Override
    public SessionPayload getSessionPayload() {
        return sessionPayload;
    }

    public void setSessionPayload(SessionPayload sessionPayload) {
        this.sessionPayload = sessionPayload;
    }

    @Override
    public String toString() {
        return "PsiAbstractServer{" +
                "sessionId=" + sessionId +
                ", threads=" + threads +
                ", sessionPayload=" + sessionPayload +
                '}';
    }
}
