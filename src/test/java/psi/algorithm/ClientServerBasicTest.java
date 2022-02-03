package psi.algorithm;

import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.helper.PsiValidationHelper;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.model.PsiClientSession;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;
import psi.server.PsiServerSession;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientServerBasicTest {

    private PsiClient psiClient;
    private PsiServerSession psiServerSession;

    private Set<String> serverDataset;
    private Set<String> clientDataset;


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

    private void initServerAndClient(PsiAlgorithmParameter psiAlgorithmParameter){
        this.psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(this.psiServerSession);
        this.psiClient = PsiClientFactory.loadSession(psiClientSession);
    }

    @Test
    void computePsi(){
        long serverSize = 300;
        long clientSize = 150;
        long intersectionSize = 100;
        initDatasets(serverSize, clientSize, intersectionSize);

        List<PsiAlgorithmParameter> supportedPsiAlgorithmParameter = PsiAlgorithm.getSupportedPsiAlgorithmParameter();
        assertEquals(8, supportedPsiAlgorithmParameter.size());

        for(PsiAlgorithmParameter psiAlgorithmParameter : supportedPsiAlgorithmParameter) {
            initServerAndClient(psiAlgorithmParameter);

            // Get server instance
            PsiServer psiServer = PsiServerFactory.loadSession(this.psiServerSession);

            // Client loads the double encrypted client dataset map
            Map<Long, String> clientEncryptedDatasetMap = this.psiClient.loadAndEncryptClientDataset(this.clientDataset);
            Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
            this.psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);

            // Client loads the encrypted server dataset
            Set<String> serverEncryptedDataset = psiServer.encryptDataset(this.serverDataset);
            this.psiClient.loadAndProcessServerDataset(serverEncryptedDataset);

            // Compute PSI
            Set<String> psiResult = this.psiClient.computePsi();
            assertEquals(intersectionSize, psiResult.size());
            assertTrue(PsiValidationHelper.validateResult(this.serverDataset, this.clientDataset, psiResult));
        }
    }

}