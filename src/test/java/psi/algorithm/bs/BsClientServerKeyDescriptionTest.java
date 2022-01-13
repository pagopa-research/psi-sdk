package psi.algorithm.bs;

import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.dto.SessionDTO;
import psi.dto.SessionParameterDTO;
import psi.exception.CustomRuntimeException;
import psi.helper.PsiValidationHelper;
import psi.mapper.SessionDtoMapper;
import psi.model.BsKeyDescription;
import psi.model.BsServerSession;
import psi.model.KeyDescription;
import psi.model.ServerSession;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;

import java.security.Key;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BsClientServerKeyDescriptionTest {

    private PsiClient psiClient;
    private ServerSession serverSession;
    private KeyDescription keyDescription;

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

    public void initKeyDescription(){
        SessionParameterDTO sessionParameterDTO = new SessionParameterDTO();
        sessionParameterDTO.setAlgorithm("BS");
        sessionParameterDTO.setKeySize(2048);
        ServerSession serverSession = PsiServerFactory.initSession(sessionParameterDTO);
        if(!(serverSession instanceof BsServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        BsKeyDescription bsKeyDescription = new BsKeyDescription();
        bsKeyDescription.setModulus(bsServerSession.getModulus());
        bsKeyDescription.setPrivateKey(bsServerSession.getServerPrivateKey());
        bsKeyDescription.setPublicKey(bsServerSession.getServerPublicKey());
        this.keyDescription = bsKeyDescription;
    }

    public void initServerAndClient(){
        SessionParameterDTO sessionParameterDTO = new SessionParameterDTO();
        sessionParameterDTO.setAlgorithm("BS");
        sessionParameterDTO.setKeySize(2048);
        ServerSession serverSession = PsiServerFactory.initSession(sessionParameterDTO, keyDescription);

        this.serverSession = serverSession;
        SessionDTO sessionDTO = SessionDtoMapper.getSessionDtoFromServerSession(serverSession, 1);
        psiClient = PsiClient.initSession(sessionDTO);
    }

    @Test
    public void computeBsPsi(){
        initKeyDescription();
        initServerDataset();
        initClientDataset();
        initServerAndClient();

        // Verify that the keys of the serverSession matchethose of the keyDescription
        if(!(serverSession instanceof BsServerSession))
            throw new CustomRuntimeException("serverSession is not an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        if(!(keyDescription instanceof BsKeyDescription))
            throw new CustomRuntimeException("keyDescription is not an instance of the subclass BsKeyDescription");
        BsKeyDescription bsKeyDescription = (BsKeyDescription) keyDescription;
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
