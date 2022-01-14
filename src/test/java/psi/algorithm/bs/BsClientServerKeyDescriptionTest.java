package psi.algorithm.bs;

import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.client.algorithm.bs.model.BsPsiClientKeyDescription;
import psi.client.model.PsiClientKeyDescription;
import psi.dto.PsiSessionDTO;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.exception.CustomRuntimeException;
import psi.helper.PsiValidationHelper;
import psi.mapper.SessionDtoMapper;
import psi.server.algorithm.bs.model.BsPsiServerKeyDescription;
import psi.server.algorithm.bs.model.BsServerSession;
import psi.server.model.PsiServerKeyDescription;
import psi.server.model.ServerSession;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BsClientServerKeyDescriptionTest {

    private PsiClient psiClient;
    private ServerSession serverSession;
    private PsiServerKeyDescription psiServerKeyDescription;
    private PsiClientKeyDescription psiClientKeyDescription;

    private Set<String> serverDataset;
    private Map<Long, String> clientDatasetMap;


    public void initClientDataset(){
        Map<Long, String> localClientDatasetMap = new HashMap<>();
        long last = 0;
        long i;
        for(i = 0; i < 1000; i ++){
            localClientDatasetMap.put(i, "MATCHING-"+i);
            last = i+1;
        }
        for(; i < last+1000; i ++){
            localClientDatasetMap.put(i, "CLIENT-ONLY-"+i);
        }
        this.clientDatasetMap = localClientDatasetMap;
    }

    public void initServerDataset(){
        Set<String> localServerDataset = new HashSet<>();
        for(long i = 0; i < 1000; i ++){
            localServerDataset.add("MATCHING-"+i);
        }

        for(long i = 0; i < 1000; i ++){
            localServerDataset.add("SERVER-ONLY-"+i);
        }
        this.serverDataset = localServerDataset;
    }

    public void initKeyDescriptions(){
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
        this.psiServerKeyDescription = bsServerKeyDescription;

        BsPsiClientKeyDescription bsPsiClientKeyDescription = new BsPsiClientKeyDescription();
        bsPsiClientKeyDescription.setServerPublicKey(bsServerKeyDescription.getPublicKey());
        bsPsiClientKeyDescription.setModulus(bsServerKeyDescription.getModulus());
        this.psiClientKeyDescription = bsPsiClientKeyDescription;
    }

    public void initServerAndClient(){
        PsiAlgorithmParameterDTO psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        psiAlgorithmParameterDTO.setAlgorithm("BS");
        psiAlgorithmParameterDTO.setKeySize(2048);
        ServerSession serverSession = PsiServerFactory.initSession(psiAlgorithmParameterDTO, psiServerKeyDescription);
        this.serverSession = serverSession;
        PsiSessionDTO psiSessionDTO = SessionDtoMapper.getSessionDtoFromServerSession(serverSession, 1);
        psiClient = PsiClientFactory.loadSession(psiSessionDTO, psiClientKeyDescription);
    }

    @Test
    public void computeBsPsi(){
        initKeyDescriptions();
        initServerDataset();
        initClientDataset();
        initServerAndClient();

        // Verify that the keys of the serverSession match those of the keyDescription
        if(!(serverSession instanceof BsServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        if(!(psiServerKeyDescription instanceof BsPsiServerKeyDescription))
            throw new CustomRuntimeException("keyDescription is not an instance of the subclass BsKeyDescription");
        BsPsiServerKeyDescription bsKeyDescription = (BsPsiServerKeyDescription) psiServerKeyDescription;
        assertEquals(bsServerSession.getServerPrivateKey(), bsKeyDescription.getPrivateKey());
        assertEquals(bsServerSession.getServerPublicKey(), bsKeyDescription.getPublicKey());
        assertEquals(bsServerSession.getModulus(), bsKeyDescription.getModulus());

        // Get server instance
        PsiServer psiServer = PsiServerFactory.loadSession(serverSession);

        // Client loads the double encrypted client dataset map
        Map<Long, String> clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDatasetMap);
        Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);

        // Client loads the encrypted server dataset
        Set<String> serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
        psiClient.loadServerDataset(serverEncryptedDataset);

        // Compute PSI
        Set<String> psiResult = psiClient.computePsi();
        assertEquals(1000, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDatasetMap, psiResult));
    }
}
