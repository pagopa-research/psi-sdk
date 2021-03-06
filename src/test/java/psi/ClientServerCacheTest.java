package psi;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.client.PsiClient;
import psi.exception.UnsupportedKeySizeException;
import psi.model.*;
import psi.server.PsiServer;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class that verifies the correct behaviour when using the cache.
 */
class ClientServerCacheTest {

    private static final Logger log = LoggerFactory.getLogger(ClientServerCacheTest.class);

    private PsiServerKeyDescription psiServerKeyDescription;
    private PsiClientKeyDescription psiClientKeyDescription;

    private Set<String> serverDataset;
    private Set<String> clientDataset;

    private PsiCacheProviderImplementation serverCache;
    private PsiCacheProviderImplementation clientCache;

    private void initDatasets(long serverSize, long clientSize, long intersectionSize) {
        initServerDataset(intersectionSize, serverSize-intersectionSize);
        initClientDataset(intersectionSize, clientSize-intersectionSize);
    }

    private void initClientDataset(long matching, long mismatching){
        this.clientDataset = new HashSet<>();
        for(long i = 0; i < matching; i ++)
            this.clientDataset.add("MATCHING-"+i);
        for(long i = matching; i < (matching + mismatching); i ++)
            this.clientDataset.add("CLIENT-ONLY-"+i);
    }

    private void initServerDataset(long matching, long mismatching){
        this.serverDataset = new HashSet<>();
        for(long i = 0; i < matching; i ++)
            this.serverDataset.add("MATCHING-"+i);
        for(long i = 0; i < mismatching; i ++)
            this.serverDataset.add("SERVER-ONLY-"+i);
    }

    private void initKeyDescriptions(PsiAlgorithmParameter psiAlgorithmParameter) throws UnsupportedKeySizeException {
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
        this.psiServerKeyDescription = psiServerSession.getPsiServerKeyDescription();
        this.psiClientKeyDescription = PsiClientFactory.loadSession(PsiClientSession.getFromServerSession(psiServerSession)).getClientKeyDescription();
    }

    private void initCache(){
        // Initializing caches
        this.serverCache = new PsiCacheProviderImplementation();
        this.clientCache = new PsiCacheProviderImplementation();
    }

    @Test
    void computePsiWithCache() throws UnsupportedKeySizeException {
        long serverSize = 30;
        long clientSize = 20;
        long intersectionSize = 10;
        initDatasets(serverSize, clientSize, intersectionSize);

        List<PsiAlgorithmParameter> supportedPsiAlgorithmParameter = PsiAlgorithm.getSupportedPsiAlgorithmParameter();
        assertEquals(16, supportedPsiAlgorithmParameter.size());

        for (PsiAlgorithmParameter psiAlgorithmParameter : supportedPsiAlgorithmParameter) {
            log.info("Running client-server cache test with {}", psiAlgorithmParameter);
            initKeyDescriptions(psiAlgorithmParameter);
            initCache();

            PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter, this.psiServerKeyDescription, this.serverCache);

            long expectedServerCacheSize = 0;
            PsiServer psiServer = null;
            PsiClient psiClient = null;
            for(int i = 0 ; i < 2 ; i++) {
                // Get client instance
                PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(psiServerSession);
                psiClient = PsiClientFactory.loadSession(psiClientSession, this.psiClientKeyDescription, this.clientCache);

                // Get server instance
                psiServer = PsiServerFactory.loadSession(psiServerSession, this.serverCache);
                expectedServerCacheSize = (i==0) ? expectedServerCacheSize + 1 : expectedServerCacheSize;
                assertEquals(expectedServerCacheSize, this.serverCache.size());

                // Server encrypts its dataset
                assertNotNull(psiServer);
                Set<String> serverEncryptedDataset = psiServer.encryptDataset(this.serverDataset);
                expectedServerCacheSize = (i==0) ? expectedServerCacheSize + serverSize : expectedServerCacheSize;
                assertEquals(expectedServerCacheSize, this.serverCache.size());

                // Client encrypts its dataset
                Map<Long, String> clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(this.clientDataset);

                // Server double encrypt client dataset
                Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
                psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);
                expectedServerCacheSize = (i==0) ? expectedServerCacheSize + clientSize : expectedServerCacheSize;
                assertEquals(expectedServerCacheSize, this.serverCache.size());

                // Client loads the encrypted server dataset
                psiClient.loadAndProcessServerDataset(serverEncryptedDataset);

                // Compute PSI
                Set<String> psiResult = psiClient.computePsi();
                assertEquals(intersectionSize, psiResult.size());
                assertTrue(PsiValidationHelper.validateResult(this.serverDataset, this.clientDataset, psiResult));
            }

            // The number of element stored into the cache depends on the algorithm involved
            if(psiAlgorithmParameter.getAlgorithm().equals(PsiAlgorithm.DH) || psiAlgorithmParameter.getAlgorithm().equals(PsiAlgorithm.ECDH))
                assertEquals(1 + clientSize + serverSize, this.clientCache.size());
            else
                assertEquals(1 + clientSize * 2, this.clientCache.size());

            // We check whether the cache was used correctly by reading stats acquired during the execution
            for (PsiPhaseStatistics sf : psiServer.getStatisticList()) {
                if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.ENCRYPTION)) {
                    assertEquals(serverSize, sf.getCacheHit());
                    assertEquals(0, sf.getCacheMiss());
                } else if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.DOUBLE_ENCRYPTION)) {
                    assertEquals(clientSize, sf.getCacheHit());
                    assertEquals(0, sf.getCacheMiss());
                }
            }

            for (PsiPhaseStatistics sf : psiClient.getStatisticList()) {
                if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.ENCRYPTION)) {
                    assertEquals(clientSize, sf.getCacheHit());
                    assertEquals(0, sf.getCacheMiss());
                } else if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.REVERSE_MAP)) {
                    assertEquals(clientSize, sf.getCacheHit());
                    assertEquals(0, sf.getCacheMiss());
                } else if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.DOUBLE_ENCRYPTION)) {
                    assertEquals(serverSize, sf.getCacheHit());
                    assertEquals(0, sf.getCacheMiss());
                }
            }
        }
    }
}