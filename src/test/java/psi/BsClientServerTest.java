package psi;

import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.dto.SessionDTO;
import psi.dto.SessionParameterDTO;
import psi.helper.PsiValidationHelper;
import psi.mapper.SessionDtoMapper;
import psi.server.PsiServer;
import psi.model.ServerSessionPayload;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BsClientServerTest {

    private PsiServer psiServer;
    private PsiClient psiClient;

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
        sessionParameterDTO.setDatatypeId("TEST");
        psiServer = PsiServer.initSession(sessionParameterDTO);
        if(psiServer == null)
            throw new RuntimeException("Psi server creation failed");
        ServerSessionPayload serverSessionPayload = psiServer.getSessionPayload();
        psiServer.setSessionId(1L);
        SessionDTO sessionDTO = SessionDtoMapper.getSessionDtoFromServerSessionPayload(serverSessionPayload, psiServer.getSessionId());
        psiClient = PsiClient.initSession(sessionDTO);
    }

    @Test
    public void computeBsPsi(){
        initServerDataset();
        initClientDataset();
        initServerAndClient();

        // Client loads the double encrypted client dataset map
        Map<Long, String> clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDatasetMap);
        Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(
                psiServer.getSessionPayload().getServerPrivateKey(),
                psiServer.getSessionPayload().getModulus(),
                clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);

        // Client loads the encrypted server dataset
        Set<String> serverEncryptedDataset = psiServer.encryptDataset(
                psiServer.getSessionPayload().getServerPrivateKey(),
                psiServer.getSessionPayload().getModulus(),
                serverDataset);
        psiClient.loadServerDataset(serverEncryptedDataset);

        // Compute PSI
        Set<String> psiResult = psiClient.computePsi();
        assertEquals(1000, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDatasetMap, psiResult));
    }
}
