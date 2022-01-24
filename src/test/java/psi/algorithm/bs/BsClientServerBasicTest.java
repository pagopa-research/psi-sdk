package psi.algorithm.bs;

import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.model.PsiClientSession;
import psi.model.PsiAlgorithmParameter;
import psi.helper.PsiValidationHelper;
import psi.model.PsiAlgorithm;
import psi.server.PsiServerSession;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BsClientServerBasicTest {

    private PsiClient psiClient;
    private PsiServerSession psiServerSession;

    private Set<String> serverDataset;
    private Set<String> clientDataset;


    public void initClientDataset(){
        Set<String> localClientDataset = new HashSet<>();
        for(long i = 0; i < 1000; i ++){
            localClientDataset.add("MATCHING-"+i);
        }
        for(long i = 0; i < 1000; i ++){
            localClientDataset.add("CLIENT-ONLY-"+i);
        }
        this.clientDataset = localClientDataset;
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
        PsiAlgorithmParameter psiAlgorithmParameter = new PsiAlgorithmParameter();
        psiAlgorithmParameter.setAlgorithm(PsiAlgorithm.BS);
        psiAlgorithmParameter.setKeySize(2048);
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
        this.psiServerSession = psiServerSession;
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(psiServerSession);
        psiClient = PsiClientFactory.loadSession(psiClientSession);
    }

    @Test
    public void computeBsPsi(){
        initServerDataset();
        initClientDataset();
        initServerAndClient();

        // Get server instance
        PsiServer psiServer = PsiServerFactory.loadSession(psiServerSession);

        // Client loads the double encrypted client dataset map
        Map<Long, String> clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDataset);
        Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);

        // Client loads the encrypted server dataset
        Set<String> serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
        psiClient.loadServerDataset(serverEncryptedDataset);

        // Compute PSI
        Set<String> psiResult = psiClient.computePsi();
        assertEquals(1000, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDataset, psiResult));
    }
}
