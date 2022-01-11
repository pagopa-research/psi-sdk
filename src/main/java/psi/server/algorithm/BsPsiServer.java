package psi.server.algorithm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.dto.SessionParameterDTO;
import psi.exception.CustomRuntimeException;
import psi.cache.EncryptionCacheProvider;
import psi.server.PsiAbstractServer;
import psi.model.ServerSessionPayload;
import psi.utils.CustomTypeConverter;
import psi.utils.HashFactory;
import psi.utils.PartitionHelper;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

public class BsPsiServer extends PsiAbstractServer {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public BsPsiServer(SessionParameterDTO sessionParameterDTO){
        this.threads = DEFAULT_THREADS;
        this.serverSessionPayload = new ServerSessionPayload();
        this.serverSessionPayload.setExpiration(Instant.now().plus(SESSION_DURATION_HOURS, ChronoUnit.HOURS));
        this.serverSessionPayload.setAlgorithm(sessionParameterDTO.getAlgorithm());
        this.serverSessionPayload.setKeySize(sessionParameterDTO.getKeySize());
        this.serverSessionPayload.setDatatypeId(sessionParameterDTO.getDatatypeId());
        this.serverSessionPayload.setDatatypeDescription(sessionParameterDTO.getDatatypeDescription());
        this.serverSessionPayload.setCacheEnabled(false);

        KeyPairGenerator keyGenerator;
        KeyFactory keyFactory;
        try {
            String keyType = "RSA";
            keyGenerator = KeyPairGenerator.getInstance(keyType);
            keyFactory = KeyFactory.getInstance(keyType);
        } catch (NoSuchAlgorithmException e) {
            log.error("Error ",e);
            throw new CustomRuntimeException("RSA key generator not available");
        }
        keyGenerator.initialize(sessionParameterDTO.getKeySize());
        KeyPair pair = keyGenerator.genKeyPair();

        try {
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
            serverSessionPayload.setModulus(privateKeySpec.getModulus());
            serverSessionPayload.setServerPrivateKey(privateKeySpec.getPrivateExponent());
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
            serverSessionPayload.setServerPublicKey(publicKeySpec.getPublicExponent());
        } catch (InvalidKeySpecException e) {
            log.error("Error: ", e);
            throw new CustomRuntimeException("KeySpec is invalid. " +
                    "Verify whether both the input algorithm and key size are correct and compatible.");
        }
    }

    public void enableCacheSupport(EncryptionCacheProvider encryptionCacheProvider){
        //TODO: check keyId

        this.serverSessionPayload.setCacheEnabled(true);
        this.encryptionCacheProvider = encryptionCacheProvider;

        //TODO: implement CANARY check
    }

    @Override
    public Set<String> encryptDataset(BigInteger serverPrivateKey, BigInteger modulus, Set<String> inputSet) {
        log.debug("Called encryptDataset()");
        Set<String> encryptedSet = new HashSet<>();

        List<Set<String>> partitionList = PartitionHelper.partitionSet(inputSet, this.threads);
        List<FutureTask<Set<String>>> futureTaskList = new ArrayList<>(threads);
        for(Set<String> partition : partitionList) {
            FutureTask<Set<String>> futureTask = new FutureTask<>(() -> {
                HashFactory hashFactory = new HashFactory(modulus);
                Set<String> localDataset = new HashSet<>();

                for(String stringValue : partition){
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(stringValue);
                    // Should add cache references here
                    BigInteger encryptedValue = hashFactory.hashFullDomain(bigIntegerValue);
                    encryptedValue = encryptedValue.modPow(serverSessionPayload.getServerPrivateKey(), serverSessionPayload.getModulus());
                    encryptedValue = hashFactory.hash(encryptedValue);
                    localDataset.add(CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                }
                return localDataset;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<Set<String>> ft : futureTaskList) {
            try {
                encryptedSet.addAll(ft.get());
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }
        return encryptedSet;
    }

    @Override
    public Map<Long, String> encryptDatasetMap(BigInteger serverPrivateKey, BigInteger modulus, Map<Long, String> inputMap) {
        log.debug("Called encryptDatasetMap()");
        Map<Long, String> encryptedMap = new HashMap<>();

        List<Map<Long, String>> partitionList = PartitionHelper.partitionMap(inputMap, this.threads);
        List<FutureTask<Map<Long, String>>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, String> partition : partitionList) {
            FutureTask<Map<Long, String>> futureTask = new FutureTask<>(() -> {
                Map<Long, String> localDatasetMap = new HashMap<>();
                for(Map.Entry<Long, String> entry : partition.entrySet()){
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(entry.getValue());
                    // Should add cache references here
                    BigInteger encryptedValue = bigIntegerValue.modPow(serverSessionPayload.getServerPrivateKey(), serverSessionPayload.getModulus());
                    localDatasetMap.put(entry.getKey(), CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                }
                return localDatasetMap;

            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<Map<Long, String>> ft : futureTaskList) {
            try {
                encryptedMap.putAll(ft.get());
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }
        return encryptedMap;
    }
}
