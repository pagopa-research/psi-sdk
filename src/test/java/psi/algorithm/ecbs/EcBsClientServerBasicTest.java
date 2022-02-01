package psi.algorithm.ecbs;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP521R1Point;
import org.junit.jupiter.api.Test;
import psi.client.PsiClient;
import psi.client.PsiClientFactory;
import psi.helper.PsiValidationHelper;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.model.PsiClientSession;
import psi.server.*;
import psi.utils.AsymmetricKeyFactory;
import psi.utils.EllipticCurve;

import java.io.*;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class EcBsClientServerBasicTest {

    private PsiClient psiClient;
    private PsiServerSession psiServerSession;

    private PsiAlgorithmParameter psiAlgorithmParameter;

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
        this.psiAlgorithmParameter = new PsiAlgorithmParameter();
        this.psiAlgorithmParameter.setAlgorithm(PsiAlgorithm.ECBS);
        this.psiAlgorithmParameter.setKeySize(256);
        PsiServerSession psiServerSession = PsiServerFactory.initSession(psiAlgorithmParameter);
        this.psiServerSession = psiServerSession;
        PsiClientSession psiClientSession = PsiClientSession.getFromServerSession(psiServerSession);
        psiClient = PsiClientFactory.loadSession(psiClientSession);
    }

    @Test
    public void computeEcBsPsi(){
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
        psiClient.loadAndProcessServerDataset(serverEncryptedDataset);

        // Compute PSI
        Set<String> psiResult = psiClient.computePsi();
        assertEquals(1000, psiResult.size());
        assertTrue(PsiValidationHelper.validateResult(serverDataset, clientDataset, psiResult));
    }

}