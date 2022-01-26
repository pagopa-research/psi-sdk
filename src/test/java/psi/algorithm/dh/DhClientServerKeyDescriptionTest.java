package psi.algorithm.dh;

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
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DhClientServerKeyDescriptionTest {

    private PsiClient psiClient;
    private PsiServerSession psiServerSession;
    private PsiServerKeyDescription psiServerKeyDescription;
    private PsiClientKeyDescription psiClientKeyDescription;

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

    public void initKeyDescriptions(){
        PsiAlgorithmParameter psiAlgorithmParameter = new PsiAlgorithmParameter();
        psiAlgorithmParameter.setAlgorithm(PsiAlgorithm.DH);
        psiAlgorithmParameter.setKeySize(2048);
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
        this.psiServerKeyDescription = psiServerSession.getPsiServerKeyDescription();
        //TODO: this is not correct and is used only for testing purposes
        this.psiClientKeyDescription = PsiClientKeyDescriptionFactory.createDhClientKeyDescription(
                AsymmetricKeyFactory.generateServerKey(PsiAlgorithm.DH, 2048).getPrivateKey(),
                this.psiServerKeyDescription.getModulus());
    }

    public void initServerAndClient(){
        PsiAlgorithmParameter psiAlgorithmParameter = new PsiAlgorithmParameter();
        psiAlgorithmParameter.setAlgorithm(PsiAlgorithm.DH);
        psiAlgorithmParameter.setKeySize(2048);
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter, psiServerKeyDescription);
        this.psiServerSession = psiServerSession;
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(psiServerSession);
        psiClient = PsiClientFactory.loadSession(psiClientSession, psiClientKeyDescription);
    }

    @Test
    public void computeDhPsi(){
        initKeyDescriptions();
        initServerDataset();
        initClientDataset();
        initServerAndClient();

        // Verify that the keys of the serverSession match those of the keyDescription
        assertEquals(this.psiServerSession.getPsiServerKeyDescription().getPrivateKey(), psiServerKeyDescription.getPrivateKey());
        assertEquals(this.psiServerSession.getPsiServerKeyDescription().getModulus(), psiServerKeyDescription.getModulus());

        // Get server instance
        PsiServer psiServer = PsiServerFactory.loadSession(psiServerSession);

        // Client loads the double encrypted client dataset map
        Map<Long, String> clientEncryptedDatasetMap = psiClient.loadAndEncryptClientDataset(clientDataset);
        Map<Long, String> doubleEncryptedClientDatasetMap = psiServer.encryptDatasetMap(clientEncryptedDatasetMap);
        psiClient.loadDoubleEncryptedClientDataset(doubleEncryptedClientDatasetMap);

        // Client loads the encrypted server dataset
        Set<String> serverEncryptedDataset = psiServer.encryptDataset(serverDataset);
        psiClient.loadAndProcessServerDataset(serverEncryptedDataset);

        // Compute PSI
        Set<String> psiResult = psiClient.computePsi();
        assertEquals(1000, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDataset, psiResult));
    }
}