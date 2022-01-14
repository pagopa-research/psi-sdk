package psi.algorithm.bs;

import org.junit.jupiter.api.Test;
import psi.cache.PsiCacheProviderImplementation;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
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
    private BsPsiServerKeyDescription keyDescription;

    private Set<String> serverDataset;
    private Map<Long, String> clientDatasetMap;

    private PsiCacheProviderImplementation serverCache;
    private PsiCacheProviderImplementation clientCache;

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

    public void initKeyDescription(){
        PsiAlgorithmParameterDTO psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        psiAlgorithmParameterDTO.setAlgorithm("BS");
        psiAlgorithmParameterDTO.setKeySize(2048);
        ServerSession serverSession = PsiServerFactory.initSession(psiAlgorithmParameterDTO);
        if(!(serverSession instanceof BsServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        BsPsiServerKeyDescription bsServerKeyDescription = new BsPsiServerKeyDescription();
        bsServerKeyDescription.setModulus(bsServerSession.getModulus());
        bsServerKeyDescription.setPrivateKey(bsServerSession.getServerPrivateKey());
        bsServerKeyDescription.setPublicKey(bsServerSession.getServerPublicKey());
        bsServerKeyDescription.setKeyId(1L);
        this.keyDescription = bsServerKeyDescription;
    }

    private void initCaches(){
        this.serverCache = new PsiCacheProviderImplementation();
        this.clientCache = new PsiCacheProviderImplementation();
    }

    private void initServerAndClient(){
        PsiAlgorithmParameterDTO psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        psiAlgorithmParameterDTO.setAlgorithm("BS");
        psiAlgorithmParameterDTO.setKeySize(2048);

        this.serverSession = PsiServerFactory.initSession(psiAlgorithmParameterDTO, this.keyDescription, this.serverCache);;
        PsiSessionDTO psiSessionDTO = SessionDtoMapper.getSessionDtoFromServerSession(serverSession, 1);
        psiClient = PsiClientFactory.loadSession(psiSessionDTO);
    }

    @Test
    public void computeBsPsi(){
        long serverSize = 3000;
        long clientSize = 1500;
        long intersectionSize = 1000;
        initKeyDescription();
        initDatasets(serverSize, clientSize, intersectionSize);
        initCaches();
        initServerAndClient();

        // Verify that the keys of the serverSession matches those of the keyDescription
        if(!(serverSession instanceof BsServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        if(!(keyDescription instanceof BsPsiServerKeyDescription))
            throw new CustomRuntimeException("keyDescription is not an instance of the subclass BsPsiServerKeyDescription");
        BsPsiServerKeyDescription bsKeyDescription = (BsPsiServerKeyDescription) keyDescription;
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
        psiServer = PsiServerFactory.loadSession(serverSession, serverCache);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Server encrypts its dataset
        serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
        assertEquals(serverSize + clientSize + 1, serverCache.size());

        // Client loads the double encrypted client dataset map
        clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDatasetMap);
        doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);
        assertEquals(serverSize + clientSize*2 + 1, serverCache.size());

        // Client loads the encrypted server dataset
        psiClient.loadServerDataset(serverEncryptedDataset);

        // Compute PSI
        psiResult = psiClient.computePsi();
        assertEquals(intersectionSize, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDatasetMap, psiResult));

        for(StatisticsFactory sf : psiServer.getStatisticList()) {
            if (sf.getDescription().equals(StatisticsFactory.PsiPhase.ENCRYPTION)) {
                assertEquals(sf.getCacheHit(), serverSize);
                assertEquals(sf.getCacheMiss(), 0);
            }
            else if (sf.getDescription().equals(StatisticsFactory.PsiPhase.DOUBLE_ENCRYPTION)) {
                assertEquals(sf.getCacheHit(), 0);
                assertEquals(sf.getCacheMiss(), clientSize);
            }
        }

        psiServer.getStatisticList().forEach(System.out::println);
    }
}
