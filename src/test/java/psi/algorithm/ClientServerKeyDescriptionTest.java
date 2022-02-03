package psi.algorithm;

import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.client.PsiClientKeyDescription;
import psi.client.PsiClientKeyDescriptionFactory;
import psi.helper.PsiValidationHelper;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.model.PsiClientSession;
import psi.server.PsiServer;
import psi.server.PsiServerFactory;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerSession;
import psi.utils.AsymmetricKeyFactory;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientServerKeyDescriptionTest {

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

    private void initKeyDescriptions(PsiAlgorithmParameter psiAlgorithmParameter){
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
        this.psiServerKeyDescription = psiServerSession.getPsiServerKeyDescription();
        switch(psiAlgorithmParameter.getAlgorithm()){
            case BS:
                this.psiClientKeyDescription = PsiClientKeyDescriptionFactory.createBsClientKeyDescription(
                        this.psiServerKeyDescription.getPublicKey(), this.psiServerKeyDescription.getModulus());
                break;
            case DH://TODO: this is not correct and is used only for testing purposes
                this.psiClientKeyDescription = PsiClientKeyDescriptionFactory.createDhClientKeyDescription(
                        AsymmetricKeyFactory.generateServerKey(PsiAlgorithm.DH, psiAlgorithmParameter.getKeySize()).getPrivateKey(),
                        this.psiServerKeyDescription.getModulus());
                break;
            case ECBS:
                this.psiClientKeyDescription = PsiClientKeyDescriptionFactory.createEcBsClientKeyDescription(
                        this.psiServerKeyDescription.getEcPublicKey(), this.psiServerKeyDescription.getEcSpecName());
                break;
            case ECDH://TODO: this is not correct and is used only for testing purposes
                this.psiClientKeyDescription = PsiClientKeyDescriptionFactory.createEcDhClientKeyDescription(
                        AsymmetricKeyFactory.generateServerKey(PsiAlgorithm.ECDH, psiAlgorithmParameter.getKeySize()).getEcPrivateKey(),
                        this.psiServerKeyDescription.getEcSpecName());
                break;
        }
    }

    private void initServerAndClient(PsiAlgorithmParameter psiAlgorithmParameter){
        this.psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter, this.psiServerKeyDescription);;
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(this.psiServerSession);
        this.psiClient = PsiClientFactory.loadSession(psiClientSession, this.psiClientKeyDescription);
    }

    @Test
    void computeEcBsPsi(){
        long serverSize = 300;
        long clientSize = 150;
        long intersectionSize = 100;
        initDatasets(serverSize, clientSize, intersectionSize);

        List<PsiAlgorithmParameter> supportedPsiAlgorithmParameter = PsiAlgorithm.getSupportedPsiAlgorithmParameter();
        assertEquals(8, supportedPsiAlgorithmParameter.size());

        for(PsiAlgorithmParameter psiAlgorithmParameter : supportedPsiAlgorithmParameter) {
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
