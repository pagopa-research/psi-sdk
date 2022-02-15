package psi;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.client.PsiClient;
import psi.exception.UnsupportedKeySizeException;
import psi.exception.UnsupportedKeySizeRuntimeException;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.model.PsiClientSession;
import psi.server.PsiServer;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class to verify the correct behaviour while using internally generated keys.
 */
class ClientServerBasicTest {

    private static final Logger log = LoggerFactory.getLogger(ClientServerBasicTest.class);

    private PsiClient psiClient;
    private PsiServerSession psiServerSession;

    private Set<String> serverDataset;
    private Set<String> clientDataset;


    private void initDatasets(long serverSize, long clientSize, long intersectionSize) {
        initServerDataset(intersectionSize, serverSize - intersectionSize);
        initClientDataset(intersectionSize, clientSize - intersectionSize);
    }

    private void initClientDataset(long matching, long mismatching) {
        this.clientDataset = new HashSet<>();
        for (long i = 0; i < matching; i++)
            this.clientDataset.add("MATCHING-" + i);
        for (long i = matching; i < (matching + mismatching); i++)
            this.clientDataset.add("CLIENT-ONLY-" + i);
    }

    private void initServerDataset(long matching, long mismatching) {
        this.serverDataset = new HashSet<>();
        for (long i = 0; i < matching; i++)
            this.serverDataset.add("MATCHING-" + i);
        for (long i = 0; i < mismatching; i++)
            this.serverDataset.add("SERVER-ONLY-" + i);
    }

    private void initServerAndClient(PsiAlgorithmParameter psiAlgorithmParameter) throws UnsupportedKeySizeException {
        this.psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(this.psiServerSession);
        this.psiClient = PsiClientFactory.loadSession(psiClientSession);
    }

    @Test
    void computeBasicPsi() throws UnsupportedKeySizeException {
        long serverSize = 30;
        long clientSize = 20;
        long intersectionSize = 10;
        initDatasets(serverSize, clientSize, intersectionSize);

        List<PsiAlgorithmParameter> supportedPsiAlgorithmParameter = PsiAlgorithm.getSupportedPsiAlgorithmParameter();
        assertEquals(16, supportedPsiAlgorithmParameter.size());

        for (PsiAlgorithmParameter psiAlgorithmParameter : supportedPsiAlgorithmParameter) {
            log.info("Running client-server basic test with {}", psiAlgorithmParameter);
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

    @Test
    void computePsiUnsupportedKeySizeTest() throws UnsupportedKeySizeException {
        List<PsiAlgorithmParameter> psiAlgorithmParameters = new LinkedList<>();
        psiAlgorithmParameters.add(new PsiAlgorithmParameter(PsiAlgorithm.BS, 160));
        psiAlgorithmParameters.add(new PsiAlgorithmParameter(PsiAlgorithm.DH, 256));
        psiAlgorithmParameters.add(new PsiAlgorithmParameter(PsiAlgorithm.ECBS, 2048));
        psiAlgorithmParameters.add(new PsiAlgorithmParameter(PsiAlgorithm.ECDH, 4096));

        // Checking that the initSession throws UnsupportedKeySizeException
        for (PsiAlgorithmParameter psiAlgorithmParameter : psiAlgorithmParameters)
            assertThrows(UnsupportedKeySizeException.class, () -> PsiServerFactory.initSession(psiAlgorithmParameter));

        // We create a correct psiServerSession and then set the key size to an invalid value to test that
        // loadSession() of the server throws UnsupportedKeySizeRuntimeExceptions and that the loadSession() of the
        // client correctly throws UnsupportedKeySizeExceptions
        List<PsiServerSession> psiServerSessionCorrectList = new LinkedList<>();
        psiServerSessionCorrectList.add(PsiServerFactory.initSession(new PsiAlgorithmParameter(PsiAlgorithm.BS, 2048)));
        psiServerSessionCorrectList.add(PsiServerFactory.initSession(new PsiAlgorithmParameter(PsiAlgorithm.DH, 2048)));
        psiServerSessionCorrectList.add(PsiServerFactory.initSession(new PsiAlgorithmParameter(PsiAlgorithm.ECBS, 256)));
        psiServerSessionCorrectList.add(PsiServerFactory.initSession(new PsiAlgorithmParameter(PsiAlgorithm.ECDH, 256)));
        for (PsiServerSession psiServerSession : psiServerSessionCorrectList) {
            switch (psiServerSession.getPsiAlgorithmParameter().getAlgorithm()) {
                case BS:
                    psiServerSession.setPsiAlgorithmParameter(new PsiAlgorithmParameter(PsiAlgorithm.BS, 160));
                    break;
                case DH:
                    psiServerSession.setPsiAlgorithmParameter(new PsiAlgorithmParameter(PsiAlgorithm.DH, 256));
                    break;
                case ECBS:
                    psiServerSession.setPsiAlgorithmParameter(new PsiAlgorithmParameter(PsiAlgorithm.ECBS, 2048));
                    break;
                case ECDH:
                    psiServerSession.setPsiAlgorithmParameter(new PsiAlgorithmParameter(PsiAlgorithm.ECDH, 4096));
                    break;
            }
            assertThrows(UnsupportedKeySizeRuntimeException.class, () -> PsiServerFactory.loadSession(psiServerSession));
            assertThrows(UnsupportedKeySizeException.class, () -> PsiClientFactory.loadSession(PsiClientSession.getFromServerSession(psiServerSession)));
        }
    }
}