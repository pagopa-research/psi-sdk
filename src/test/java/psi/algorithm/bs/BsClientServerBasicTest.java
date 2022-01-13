package psi.algorithm.bs;

import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.dto.SessionDTO;
import psi.dto.SessionParameterDTO;
import psi.helper.PsiValidationHelper;
import psi.mapper.SessionDtoMapper;
import psi.model.ServerSession;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BsClientServerBasicTest {

    private PsiClient psiClient;
    private ServerSession serverSession;

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

    public void initServerAndClient(){
        SessionParameterDTO sessionParameterDTO = new SessionParameterDTO();
        sessionParameterDTO.setAlgorithm("BS");
        sessionParameterDTO.setKeySize(2048);
        ServerSession serverSession = PsiServerFactory.initSession(sessionParameterDTO);
        this.serverSession = serverSession;
        SessionDTO sessionDTO = SessionDtoMapper.getSessionDtoFromServerSession(serverSession, 1);
        psiClient = PsiClient.initSession(sessionDTO);
    }

    @Test
    public void computeBsPsi(){
        initServerDataset();
        initClientDataset();
        initServerAndClient();

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
