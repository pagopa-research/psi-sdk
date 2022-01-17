package psi.algorithm.bs;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import psi.cache.PsiCacheProviderImplementation;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.client.algorithm.bs.model.BsPsiClientKeyDescription;
import psi.client.model.PsiClientKeyDescription;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.dto.PsiSessionDTO;
import psi.exception.CustomRuntimeException;
import psi.helper.PsiValidationHelper;
import psi.mapper.SessionDtoMapper;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;
import psi.server.algorithm.bs.model.BsPsiServerKeyDescription;
import psi.server.algorithm.bs.model.BsServerSession;
import psi.server.model.ServerSession;
import psi.utils.StatisticsFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BsClientServerCacheTest {

    private PsiClient psiClient;
    private ServerSession serverSession;
    private BsPsiServerKeyDescription psiServerKeyDescription;
    private PsiClientKeyDescription psiClientKeyDescription;
    private PsiAlgorithmParameterDTO psiAlgorithmParameterDTO;

    private Set<String> serverDataset;
    private Map<Long, String> clientDatasetMap;

    private PsiCacheProviderImplementation serverCache;
    private PsiCacheProviderImplementation clientCache;

    private int sessionId;

    private void setup() {
        // Initializing key descriptions
        this.psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        this.psiAlgorithmParameterDTO.setAlgorithm("BS");
        this.psiAlgorithmParameterDTO.setKeySize(2048);
        ServerSession serverSession = PsiServerFactory.initSession(this.psiAlgorithmParameterDTO);
        if(!(serverSession instanceof BsServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        BsPsiServerKeyDescription bsServerKeyDescription = new BsPsiServerKeyDescription();
        bsServerKeyDescription.setModulus(bsServerSession.getModulus());
        bsServerKeyDescription.setPrivateKey(bsServerSession.getServerPrivateKey());
        bsServerKeyDescription.setPublicKey(bsServerSession.getServerPublicKey());
        bsServerKeyDescription.setKeyId(1L);
        this.psiServerKeyDescription = bsServerKeyDescription;

        BsPsiClientKeyDescription bsPsiClientKeyDescription = new BsPsiClientKeyDescription();
        bsPsiClientKeyDescription.setServerPublicKey(bsServerKeyDescription.getPublicKey());
        bsPsiClientKeyDescription.setModulus(bsServerKeyDescription.getModulus());
        bsPsiClientKeyDescription.setKeyId(2L);
        this.psiClientKeyDescription = bsPsiClientKeyDescription;

        // Initializing caches
        this.serverCache = new PsiCacheProviderImplementation();
        this.clientCache = new PsiCacheProviderImplementation();

        this.sessionId = 1;
    }

    private void initDatasets(long serverSize, long clientSize, long intersectionSize) {
        initServerDataset(intersectionSize, serverSize-intersectionSize);
        initClientDataset(intersectionSize, clientSize-intersectionSize);
    }

    private void initClientDataset(long matching, long mismatching){
        this.clientDatasetMap = new HashMap<>();
        for(long i = 0; i < matching; i ++)
            this.clientDatasetMap.put(i, "MATCHING-"+i);
        for(long i = matching; i < (matching + mismatching); i ++)
            this.clientDatasetMap.put(i, "CLIENT-ONLY-"+i);

    }

    private void initServerDataset(long matching, long mismatching){
        this.serverDataset = new HashSet<>();
        for(long i = 0; i < matching; i ++)
            this.serverDataset.add("MATCHING-"+i);
        for(long i = 0; i < mismatching; i ++)
            this.serverDataset.add("SERVER-ONLY-"+i);
    }

    private void initServerAndClient(boolean cacheEnabledServer, boolean cacheEnabledClient, int sessionId ){
        if(sessionId == 1) {
            if (cacheEnabledServer)
                this.serverSession = PsiServerFactory.initSession(this.psiAlgorithmParameterDTO, this.psiServerKeyDescription, this.serverCache);
            else
                this.serverSession = PsiServerFactory.initSession(this.psiAlgorithmParameterDTO, this.psiServerKeyDescription);
        }
        PsiSessionDTO psiSessionDTO = SessionDtoMapper.getSessionDtoFromServerSession(serverSession, sessionId);
        if (cacheEnabledClient)
            psiClient = PsiClientFactory.loadSession(psiSessionDTO,this.psiClientKeyDescription, this.clientCache);
        else
            psiClient = PsiClientFactory.loadSession(psiSessionDTO,this.psiClientKeyDescription);

    }

    @Test
    public void computeBsPsi(){
        setup();
        long serverSize = 3000;
        long clientSize = 1500;
        long intersectionSize = 1000;
        initDatasets(serverSize, clientSize, intersectionSize);
        initServerAndClient(true, true, this.sessionId++);

        // Verify that the keys of the serverSession matches those of the keyDescription
        if(!(serverSession instanceof BsServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        if(!(psiServerKeyDescription instanceof BsPsiServerKeyDescription))
            throw new CustomRuntimeException("keyDescription is not an instance of the subclass BsPsiServerKeyDescription");
        BsPsiServerKeyDescription bsKeyDescription = (BsPsiServerKeyDescription) psiServerKeyDescription;
        assertEquals(bsServerSession.getServerPrivateKey(), bsKeyDescription.getPrivateKey());
        assertEquals(bsServerSession.getServerPublicKey(), bsKeyDescription.getPublicKey());
        assertEquals(bsServerSession.getModulus(), bsKeyDescription.getModulus());

        // Get server instance
        PsiServer psiServer = PsiServerFactory.loadSession(serverSession, serverCache);
        assertEquals(1, serverCache.size());

        // Server encrypts its dataset
        Set<String> serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
        assertEquals(serverSize + 1, serverCache.size());

        // Client loads the double encrypted client dataset map
        Map<Long, String> clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDatasetMap);
        Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Client loads the encrypted server dataset
        psiClient.loadServerDataset(serverEncryptedDataset);

        // Compute PSI
        Set<String> psiResult = psiClient.computePsi();
        assertEquals(intersectionSize, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDatasetMap, psiResult));

        // At this point I want to repeat entirely the procedure to see its effect on the cache

        // Get server instance
        //initServerAndClient(true, true, this.sessionId++);

        psiServer = PsiServerFactory.loadSession(this.serverSession, this.serverCache);
        PsiSessionDTO psiSessionDTO = SessionDtoMapper.getSessionDtoFromServerSession(this.serverSession, this.sessionId++);
        psiClient = PsiClientFactory.loadSession(psiSessionDTO,this.psiClientKeyDescription, this.clientCache);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Server encrypts its dataset
        serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Client loads the double encrypted client dataset map
        clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDatasetMap);
        doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Client loads the encrypted server dataset
        psiClient.loadServerDataset(serverEncryptedDataset);

        // Compute PSI
        psiResult = psiClient.computePsi();
        assertEquals(intersectionSize, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDatasetMap, psiResult));

        for(StatisticsFactory sf : psiServer.getStatisticList()) {
            if (sf.getDescription().equals(StatisticsFactory.PsiPhase.ENCRYPTION)) {
                assertEquals(serverSize, sf.getCacheHit());
                assertEquals(0, sf.getCacheMiss());
            }
            else if (sf.getDescription().equals(StatisticsFactory.PsiPhase.DOUBLE_ENCRYPTION)) {
                assertEquals(clientSize, sf.getCacheHit());
                assertEquals(0, sf.getCacheMiss());
            }
        }

        for(StatisticsFactory sf : psiClient.getStatisticList()) {
            if (sf.getDescription().equals(StatisticsFactory.PsiPhase.ENCRYPTION)) {
                assertEquals(clientSize, sf.getCacheHit());
                assertEquals(0, sf.getCacheMiss());
            }
            else if (sf.getDescription().equals(StatisticsFactory.PsiPhase.REVERSE_MAP)){
                assertEquals(clientSize, sf.getCacheHit());
                assertEquals(0, sf.getCacheMiss());
            }
        }
    }
}
