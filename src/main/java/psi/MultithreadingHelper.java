package psi;

import org.slf4j.Logger;
import psi.exception.CustomRuntimeException;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

class MultithreadingHelper {

    private MultithreadingHelper() {
    }

    static void awaitTermination(ExecutorService executorService, int maxSecondsLifetime, Logger log){
        try {
            executorService.shutdown();
            executorService.awaitTermination(maxSecondsLifetime, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            log.error("Error while collecting the results of threads: ", e);
            throw new CustomRuntimeException(e.getMessage());
        } finally {
            executorService.shutdown();
        }
    }
}
