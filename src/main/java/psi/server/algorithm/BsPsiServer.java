package psi.server.algorithm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.dto.SessionParameterDTO;
import psi.exception.CustomRuntimeException;
import psi.server.PsiAbstractServer;
import psi.server.model.SessionPayload;
import psi.utils.CustomTypeConverter;
import psi.utils.PartitionHelper;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAmount;
import java.time.temporal.TemporalUnit;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

public class BsPsiServer extends PsiAbstractServer {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    public BsPsiServer(SessionParameterDTO sessionParameterDTO){
        this.threads = DEFAULT_THREADS;
        this.sessionPayload = new SessionPayload();
        this.sessionPayload.setExpiration(Instant.now().plus(SESSION_DURATION_HOURS, ChronoUnit.HOURS));
        this.sessionPayload.setAlgorithm(sessionParameterDTO.getAlgorithm());
        this.sessionPayload.setKeySize(sessionParameterDTO.getKeySize());
        this.sessionPayload.setDatatypeId(sessionParameterDTO.getDatatypeId());
        this.sessionPayload.setDatatypeDescription(sessionParameterDTO.getDatatypeDescription());

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
            sessionPayload.setModulus(privateKeySpec.getModulus());
            sessionPayload.setServerPrivateKey(privateKeySpec.getPrivateExponent());
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
            sessionPayload.setServerPublicKey(publicKeySpec.getPublicExponent());
        } catch (InvalidKeySpecException e) {
            log.error("Error: ", e);
            throw new CustomRuntimeException("KeySpec is invalid. " +
                    "Verify whether both the input algorithm and key size are correct and compatible.");
        }
    }

    @Override
    public Set<String> encryptDataset(BigInteger serverPrivateKey, BigInteger modulus, Set<String> inputSet) {
        log.debug("Called encryptDataset()");
        Set<String> encryptedSet = new HashSet<>();

        List<Set<String>> partitionList = PartitionHelper.partitionSet(inputSet, this.threads);
        List<FutureTask<Set<String>>> futureTaskList = new ArrayList<>(threads);
        for(Set<String> partition : partitionList) {
            FutureTask<Set<String>> futureTask = new FutureTask<>(() -> {
                Set<String> localDataset = new HashSet<>();

                for(String stringValue : partition){
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(stringValue);
                    // Should add cache references here
                    BigInteger encryptedValue = bigIntegerValue.modPow(sessionPayload.getServerPrivateKey(), sessionPayload.getModulus());
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
                    BigInteger encryptedValue = bigIntegerValue.modPow(sessionPayload.getServerPrivateKey(), sessionPayload.getModulus());
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
