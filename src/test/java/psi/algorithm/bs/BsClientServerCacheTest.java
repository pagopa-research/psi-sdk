package psi.algorithm.bs;

import org.junit.jupiter.api.Test;
import psi.cache.PsiCacheProviderImplementation;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.client.algorithm.bs.model.BsPsiClientKeyDescription;
import psi.client.model.PsiClientKeyDescription;
import psi.dto.PsiAlgorithmDTO;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.dto.PsiSessionDTO;
import psi.exception.CustomRuntimeException;
import psi.helper.PsiValidationHelper;
import psi.mapper.SessionDtoMapper;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;
import psi.server.algorithm.bs.model.BsPsiServerKeyDescription;
import psi.server.algorithm.bs.model.BsPsiServerSession;
import psi.server.model.PsiServerSession;
import psi.utils.StatisticsFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BsClientServerCacheTest {

    private PsiClient psiClient;
    private PsiServerSession psiServerSession;
    private BsPsiServerKeyDescription psiServerKeyDescription;
    private PsiClientKeyDescription psiClientKeyDescription;
    private PsiAlgorithmParameterDTO psiAlgorithmParameterDTO;

    private Set<String> serverDataset;
    private Set<String> clientDataset;

    private PsiCacheProviderImplementation serverCache;
    private PsiCacheProviderImplementation clientCache;

    private void setup() {
        // Initializing key descriptions
        this.psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        this.psiAlgorithmParameterDTO.setAlgorithm(PsiAlgorithmDTO.BS);
        this.psiAlgorithmParameterDTO.setKeySize(2048);
        PsiServerSession psiServerSession = PsiServerFactory.initSession(this.psiAlgorithmParameterDTO);
        if(!(psiServerSession instanceof BsPsiServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsPsiServerSession bsServerSession = (BsPsiServerSession) psiServerSession;
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
        this.psiServerSession = PsiServerFactory.initSession(this.psiAlgorithmParameterDTO, this.psiServerKeyDescription, this.serverCache);
        PsiSessionDTO psiSessionDTO = SessionDtoMapper.getSessionDtoFromServerSession(psiServerSession);
        psiClient = PsiClientFactory.loadSession(psiSessionDTO,this.psiClientKeyDescription, this.clientCache);
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
        if(!(psiServerSession instanceof BsPsiServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsPsiServerSession bsServerSession = (BsPsiServerSession) psiServerSession;
        if(psiServerKeyDescription == null)
            throw new CustomRuntimeException("keyDescription is not an instance of the subclass BsPsiServerKeyDescription");
        BsPsiServerKeyDescription bsKeyDescription = psiServerKeyDescription;
        assertEquals(bsServerSession.getServerPrivateKey(), bsKeyDescription.getPrivateKey());
        assertEquals(bsServerSession.getServerPublicKey(), bsKeyDescription.getPublicKey());
        assertEquals(bsServerSession.getModulus(), bsKeyDescription.getModulus());

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
        PsiSessionDTO psiSessionDTO = SessionDtoMapper.getSessionDtoFromServerSession(this.psiServerSession);
        psiClient = PsiClientFactory.loadSession(psiSessionDTO,this.psiClientKeyDescription, this.clientCache);
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