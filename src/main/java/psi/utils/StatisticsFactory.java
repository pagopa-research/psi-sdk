package psi.utils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicLong;

public class StatisticsFactory {

    public enum PsiPhase {ENCRYPTION, DOUBLE_ENCRYPTION, PSI}

    private PsiPhase description;
    private Instant startTime;
    private Instant endTime;
    private AtomicLong cacheHit;
    private AtomicLong cacheMiss;
    private long totalTimeElapsed = 0L;

    public StatisticsFactory(PsiPhase description) {
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

    public StatisticsFactory close(long cacheHit, long cacheMiss){
        this.cacheHit = new AtomicLong(cacheHit);
        this.cacheMiss = new AtomicLong(cacheMiss);
        return close();
    }

    public StatisticsFactory close(){
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
        return "StatisticsFactory{" +
                "description='" + description + '\'' +
                ", startTime=" + startTime +
                ", endTime=" + endTime +
                ", totalTimeElapsed=" + totalTimeElapsed +
                ", processedElements=" + (cacheHit.get() + cacheMiss.get()) +
                ", cacheHit=" + cacheHit.get() +
                ", cacheMiss=" + cacheMiss.get() +
                '}';
    }
}
