package psi.algorithm;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.PsiClientFactory;
import psi.PsiServerFactory;
import psi.PsiServerSession;
import psi.PsiValidationHelper;
import psi.client.PsiClient;
import psi.client.PsiClientKeyDescription;
import psi.exception.UnsupportedKeySizeException;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.model.PsiClientSession;
import psi.server.PsiServer;
import psi.server.PsiServerKeyDescription;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientServerKeyDescriptionTest {

    private static final Logger log = LoggerFactory.getLogger(ClientServerKeyDescriptionTest.class);

    private PsiClient psiClient;
    private PsiServerSession psiServerSession;
    private PsiServerKeyDescription psiServerKeyDescription;
    private PsiClientKeyDescription psiClientKeyDescription;

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

    private void initKeyDescriptions(PsiAlgorithmParameter psiAlgorithmParameter) throws UnsupportedKeySizeException {
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
        this.psiServerKeyDescription = psiServerSession.getPsiServerKeyDescription();
        this.psiClientKeyDescription = PsiClientFactory.loadSession(PsiClientSession.getFromServerSession(psiServerSession)).getClientKeyDescription();
    }

    private void initServerAndClient(PsiAlgorithmParameter psiAlgorithmParameter) throws UnsupportedKeySizeException {
        this.psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter, this.psiServerKeyDescription);
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(this.psiServerSession);
        this.psiClient = PsiClientFactory.loadSession(psiClientSession, this.psiClientKeyDescription);
    }

    @Test
    void computeEcBsPsi() throws UnsupportedKeySizeException {
        long serverSize = 30;
        long clientSize = 20;
        long intersectionSize = 10;
        initDatasets(serverSize, clientSize, intersectionSize);

        List<PsiAlgorithmParameter> supportedPsiAlgorithmParameter = PsiAlgorithm.getSupportedPsiAlgorithmParameter();
        assertEquals(16, supportedPsiAlgorithmParameter.size());

        for (PsiAlgorithmParameter psiAlgorithmParameter : supportedPsiAlgorithmParameter) {
            log.info("Running client-server external key test with {}", psiAlgorithmParameter);
            initKeyDescriptions(psiAlgorithmParameter);
            initServerAndClient(psiAlgorithmParameter);

            // Verify that the keys of the serverSession match those of the keyDescription
            assertEquals(this.psiServerSession.getPsiServerKeyDescription().getPrivateKey(), this.psiServerKeyDescription.getPrivateKey());
            assertEquals(this.psiServerSession.getPsiServerKeyDescription().getPublicKey(), this.psiServerKeyDescription.getPublicKey());
            assertEquals(this.psiServerSession.getPsiServerKeyDescription().getModulus(), this.psiServerKeyDescription.getModulus());
            assertEquals(this.psiServerSession.getPsiServerKeyDescription().getEcPrivateKey(), this.psiServerKeyDescription.getEcPrivateKey());
            assertEquals(this.psiServerSession.getPsiServerKeyDescription().getEcPublicKey(), this.psiServerKeyDescription.getEcPublicKey());
            assertEquals(this.psiServerSession.getPsiServerKeyDescription().getEcSpecName(), this.psiServerKeyDescription.getEcSpecName());

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
