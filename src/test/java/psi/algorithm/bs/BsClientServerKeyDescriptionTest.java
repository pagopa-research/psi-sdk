package psi.algorithm.bs;

import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.client.PsiClientKeyDescriptionFactory;
import psi.client.PsiClientKeyDescription;
import psi.dto.PsiSessionDTO;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.helper.PsiValidationHelper;
import psi.mapper.SessionDTOMapper;
import psi.model.PsiAlgorithm;
import psi.server.*;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BsClientServerKeyDescriptionTest {

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
        PsiAlgorithmParameterDTO psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        psiAlgorithmParameterDTO.setAlgorithm(PsiAlgorithm.BS);
        psiAlgorithmParameterDTO.setKeySize(2048);
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameterDTO);
        this.psiServerKeyDescription = psiServerSession.getPsiServerKeyDescription();
        this.psiClientKeyDescription = PsiClientKeyDescriptionFactory.createBsClientKeyDescription(
                this.psiServerKeyDescription.getPublicKey(), this.psiServerKeyDescription.getModulus());
    }

    public void initServerAndClient(){
        PsiAlgorithmParameterDTO psiAlgorithmParameterDTO = new PsiAlgorithmParameterDTO();
        psiAlgorithmParameterDTO.setAlgorithm(PsiAlgorithm.BS);
        psiAlgorithmParameterDTO.setKeySize(2048);
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameterDTO, psiServerKeyDescription);
        this.psiServerSession = psiServerSession;
        PsiSessionDTO psiSessionDTO = SessionDTOMapper.getSessionDtoFromServerSession(psiServerSession);
        psiClient = PsiClientFactory.loadSession(psiSessionDTO, psiClientKeyDescription);
    }

    @Test
    public void computeBsPsi(){
        initKeyDescriptions();
        initServerDataset();
        initClientDataset();
        initServerAndClient();

        // Verify that the keys of the serverSession match those of the keyDescription
        assertEquals(this.psiServerSession.getPsiServerKeyDescription().getPrivateKey(), psiServerKeyDescription.getPrivateKey());
        assertEquals(this.psiServerSession.getPsiServerKeyDescription().getPublicKey(), psiServerKeyDescription.getPublicKey());
        assertEquals(this.psiServerSession.getPsiServerKeyDescription().getModulus(), psiServerKeyDescription.getModulus());

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
