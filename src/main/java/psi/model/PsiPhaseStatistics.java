package psi.model;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicLong;

public class PsiPhaseStatistics {

    public enum PsiPhase {ENCRYPTION, DOUBLE_ENCRYPTION, REVERSE_MAP, PSI}

    private final PsiPhase description;
    private final Instant startTime;
    private Instant endTime;
    private AtomicLong cacheHit;
    private AtomicLong cacheMiss;
    private long totalTimeElapsed = 0L;

    public static PsiPhaseStatistics startStatistic(PsiPhase description){
        return new PsiPhaseStatistics(description);
    }

    private PsiPhaseStatistics(PsiPhase description) {
        this.description = description;
        this.startTime = Instant.now();
        cacheHit = new AtomicLong(0);
        cacheMiss = new AtomicLong(0);
    }

    public void incrementCacheMiss(){
        this.cacheMiss.incrementAndGet();
    }

    public void incrementCacheHit(){
        this.cacheHit.incrementAndGet();
    }

    public void incrementCacheMiss(long cacheMiss){
        this.cacheMiss.addAndGet(cacheMiss);
    }

    public void incrementCacheHit(long cacheHit){
        this.cacheHit.addAndGet(cacheHit);
    }

    public PsiPhaseStatistics close(long cacheHit, long cacheMiss){
        this.cacheHit = new AtomicLong(cacheHit);
        this.cacheMiss = new AtomicLong(cacheMiss);
        return close();
    }

    public PsiPhaseStatistics close(){
        this.endTime = Instant.now();
        this.totalTimeElapsed = startTime.until(endTime, ChronoUnit.MILLIS);
        return this;
    }

    public PsiPhase getDescription() {
        return description;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getEndTime() {
        return endTime;
    }

    public long getTotalTimeElapsed() {
        return totalTimeElapsed;
    }

    public long getCacheHit() {
        return cacheHit.get();
    }

    public long getCacheMiss() {
        return cacheMiss.get();
    }

    public long getProcessedElements() {
        return cacheMiss.get() + cacheHit.get();
    }

    @Override
    public String toString() {
        return "PsiPhaseStatistics{" +
                "description=" + description +
                ", startTime=" + startTime +
                ", endTime=" + endTime +
                ", cacheHit=" + cacheHit +
                ", cacheMiss=" + cacheMiss +
                ", totalTimeElapsed=" + totalTimeElapsed +
                '}';
    }
}
