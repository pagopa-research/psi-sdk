package psi.algorithm.bs;

import org.junit.jupiter.api.Test;
import psi.cache.PsiCacheProviderImplementation;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.client.PsiClientKeyDescriptionFactory;
import psi.client.PsiClientKeyDescription;
import psi.model.PsiAlgorithmParameter;
import psi.model.PsiClientSession;
import psi.exception.CustomRuntimeException;
import psi.helper.PsiValidationHelper;
import psi.model.PsiAlgorithm;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerSession;
import psi.utils.PsiPhaseStatistics;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BsClientServerCacheTest {

    private PsiClient psiClient;
    private PsiServerSession psiServerSession;
    private PsiServerKeyDescription psiServerKeyDescription;
    private PsiClientKeyDescription psiClientKeyDescription;
    private PsiAlgorithmParameter psiAlgorithmParameter;

    private Set<String> serverDataset;
    private Set<String> clientDataset;

    private PsiCacheProviderImplementation serverCache;
    private PsiCacheProviderImplementation clientCache;

    private void setup() {
        // Initializing key descriptions
        this.psiAlgorithmParameter = new PsiAlgorithmParameter();
        this.psiAlgorithmParameter.setAlgorithm(PsiAlgorithm.BS);
        this.psiAlgorithmParameter.setKeySize(2048);
        PsiServerSession psiServerSession = PsiServerFactory.initSession(this.psiAlgorithmParameter);
        this.psiServerKeyDescription = psiServerSession.getPsiServerKeyDescription();
        this.psiClientKeyDescription = PsiClientKeyDescriptionFactory.createBsClientKeyDescription(
                this.psiServerKeyDescription.getPublicKey(), this.psiServerKeyDescription.getModulus());

        // Initializing caches
        this.serverCache = new PsiCacheProviderImplementation();
        this.clientCache = new PsiCacheProviderImplementation();
    }

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

    private void initServerAndClientWithCachesEnabled(){
        this.psiServerSession = PsiServerFactory.initSession(this.psiAlgorithmParameter, this.psiServerKeyDescription, this.serverCache);
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(psiServerSession);
        psiClient = PsiClientFactory.loadSession(psiClientSession,this.psiClientKeyDescription, this.clientCache);
    }

    @Test
    public void computeBsPsi(){
        setup();
        long serverSize = 3000;
        long clientSize = 1500;
        long intersectionSize = 1000;
        initDatasets(serverSize, clientSize, intersectionSize);
        initServerAndClientWithCachesEnabled();

        // Verify that the keys of the serverSession matches those of the keyDescription
        if(psiServerKeyDescription == null)
            throw new CustomRuntimeException("keyDescription should not be null");
        assertEquals(psiServerSession.getPsiServerKeyDescription().getPrivateKey(), psiServerKeyDescription.getPrivateKey());
        assertEquals(psiServerSession.getPsiServerKeyDescription().getPublicKey(), psiServerKeyDescription.getPublicKey());
        assertEquals(psiServerSession.getPsiServerKeyDescription().getModulus(), psiServerKeyDescription.getModulus());

        // Get server instance
        PsiServer psiServer = PsiServerFactory.loadSession(psiServerSession, serverCache);
        assertEquals(1, serverCache.size());

        // Server encrypts its dataset
        if(psiServer == null)
            throw new RuntimeException("PsiServer should not be null");
        Set<String> serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
        assertEquals(serverSize + 1, serverCache.size());

        // Client loads the double encrypted client dataset map
        Map<Long, String> clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDataset);
        Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Client loads the encrypted server dataset
        psiClient.loadServerDataset(serverEncryptedDataset);

        // Compute PSI
        Set<String> psiResult = psiClient.computePsi();
        assertEquals(intersectionSize, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDataset, psiResult));

        // We repeat the entire procedure to verify its effect on the cache
        psiServer = PsiServerFactory.loadSession(this.psiServerSession, this.serverCache);
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(this.psiServerSession);
        psiClient = PsiClientFactory.loadSession(psiClientSession,this.psiClientKeyDescription, this.clientCache);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Server encrypts its dataset
        if(psiServer == null)
            throw new RuntimeException("PsiServer should not be null");
        serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Client loads the double encrypted client dataset map
        clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDataset);
        doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Client loads the encrypted server dataset
        psiClient.loadServerDataset(serverEncryptedDataset);

        // Compute PSI
        psiResult = psiClient.computePsi();
        assertEquals(intersectionSize, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDataset, psiResult));

        // We check whether the cache was used correctly by reading stats acquired during the execution
        for(PsiPhaseStatistics sf : psiServer.getStatisticList()) {
            if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.ENCRYPTION)) {
                assertEquals(serverSize, sf.getCacheHit());
                assertEquals(0, sf.getCacheMiss());
            }
            else if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.DOUBLE_ENCRYPTION)) {
                assertEquals(clientSize, sf.getCacheHit());
                assertEquals(0, sf.getCacheMiss());
            }
        }

        for(PsiPhaseStatistics sf : psiClient.getStatisticList()) {
            if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.ENCRYPTION)) {
                assertEquals(clientSize, sf.getCacheHit());
                assertEquals(0, sf.getCacheMiss());
            }
            else if (sf.getDescription().equals(PsiPhaseStatistics.PsiPhase.REVERSE_MAP)){
                assertEquals(clientSize, sf.getCacheHit());
                assertEquals(0, sf.getCacheMiss());
            }
        }
    }
}