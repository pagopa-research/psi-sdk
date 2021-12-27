package psi.client.algorithm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.client.PsiAbstractClient;
import psi.dto.SessionDTO;
import psi.utils.CustomTypeConverter;
import psi.utils.PartitionHelper;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

public class BsPsiClient extends PsiAbstractClient {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private static final int RANDOM_BITS = 2048;

    private int threads;
    private BigInteger seed;
    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, BigInteger> clientRandomDatasetMap;
    private final Map<Long, BigInteger> clientEncryptedDatasetMap;
    private final Map<Long, BigInteger> clientDoubleEncryptedDatasetMap;
    private final Map<Long, BigInteger> clientReversedDatasetMap;

    public BsPsiClient(SessionDTO sessionDTO){
        this.sessionId = sessionDTO.getSessionId();
        this.modulus = CustomTypeConverter.convertStringToBigInteger(sessionDTO.getModulus());
        this.serverPublicKey = CustomTypeConverter.convertStringToBigInteger(sessionDTO.getServerPublicKey());
        this.serverEncryptedDataset = new HashSet<>();
        this.clientClearDatasetMap = new HashMap<>();
        this.clientRandomDatasetMap = new HashMap<>();
        this.clientEncryptedDatasetMap = new HashMap<>();
        this.clientDoubleEncryptedDatasetMap = new HashMap<>();
        this.clientReversedDatasetMap = new HashMap<>();

        // By default, a new seed for the blind signature is created. It can be overwritten with the setter method
        this.seed = new BigInteger(RANDOM_BITS, new SecureRandom());
    }

    public BigInteger getSeed() {
        return seed;
    }

    public void setSeed(BigInteger seed) {
        this.seed = seed;
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    @Override
    public Map<Long, String> loadAndEncryptClientDataset(Map<Long, String> clearClientDataset) {
        log.debug("Called loadAndEncryptClientDataset");
        List<Map<Long, String>> clientDatasetPartitions = PartitionHelper.partitionMap(clearClientDataset, this.threads);
        Map<Long, String> clientEncryptedDatasetMapConvertedToString = new HashMap<>();

        List<FutureTask<BsMapQuartet>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, String> partition : clientDatasetPartitions) {
            FutureTask<BsMapQuartet> futureTask = new FutureTask<>(() -> {
                 Map<Long, BigInteger> localClientClearDatasetMap = new HashMap<>();
                 Map<Long, BigInteger> localClientRandomDatasetMap = new HashMap<>();
                 Map<Long, BigInteger> localClientEncryptedDatasetMap = new HashMap<>();
                 Map<Long, String> localClientEncryptedDatasetMapConvertedToString = new HashMap<>();

                for(Map.Entry<Long, String> entry : partition.entrySet()){
                     BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(entry.getValue());
                     // Should add cache references here
                     BigInteger randomValue = (seed.xor(bigIntegerValue)).mod(modulus); // new BigInteger(modulus.bitCount(), secureRandom).mod(modulus)
                     BigInteger encryptedValue = randomValue.modPow(serverPublicKey, modulus).multiply(bigIntegerValue).mod(modulus);
                     localClientClearDatasetMap.put(entry.getKey(), bigIntegerValue);
                     localClientRandomDatasetMap.put(entry.getKey(), randomValue);
                     localClientEncryptedDatasetMap.put(entry.getKey(), encryptedValue);
                     localClientEncryptedDatasetMapConvertedToString.put(entry.getKey(), CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                 }

                 BsMapQuartet bsMapQuartet = new BsMapQuartet();
                 bsMapQuartet.clearMap = localClientClearDatasetMap;
                 bsMapQuartet.randomMap = localClientRandomDatasetMap;
                 bsMapQuartet.encryptedMap = localClientEncryptedDatasetMap;
                 bsMapQuartet.encryptedMapConvertedToString = localClientEncryptedDatasetMapConvertedToString;
                 return bsMapQuartet;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<BsMapQuartet> ft : futureTaskList) {
            try {
                clientClearDatasetMap.putAll(ft.get().clearMap);
                clientRandomDatasetMap.putAll(ft.get().randomMap);
                clientEncryptedDatasetMap.putAll(ft.get().encryptedMap);
                clientEncryptedDatasetMapConvertedToString.putAll(ft.get().encryptedMapConvertedToString);
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }
        return clientEncryptedDatasetMapConvertedToString;
    }

    @Override
    public void loadDoubleEncryptedClientDataset(Map<Long, String> doubleEncryptedClientDatasetMap){
        log.debug("Called loadDoubleEncryptedClientDataset");
        for(Map.Entry<Long, String> entry : doubleEncryptedClientDatasetMap.entrySet()) {
            this.clientDoubleEncryptedDatasetMap.put(entry.getKey(), CustomTypeConverter.convertStringToBigInteger(entry.getValue()));
        }
    }

    @Override
    public void loadServerDataset(Set<String> serverEncryptedDataset) {
        log.debug("Called loadServerDataset");
        for(String value : serverEncryptedDataset) {
            this.serverEncryptedDataset.add(CustomTypeConverter.convertStringToBigInteger(value));
        }
    }

     // Loads the clientReversedDatasetMap which contains a decryption of the clientDoubleEncryptedDatasetMap entries
    private void computeReversedMap(){
        log.debug("Called computeReversedMap");
        List<Map<Long, BigInteger>> doubleEncryptedMapPartition = PartitionHelper.partitionMap(clientDoubleEncryptedDatasetMap, threads);
        List<FutureTask<Map<Long, BigInteger>>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, BigInteger> partition : doubleEncryptedMapPartition){
            FutureTask<Map<Long, BigInteger>> futureTask = new FutureTask<>(() -> {
                Map<Long, BigInteger> localClientReversedDatasetMap = new HashMap<>();
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()){
                    // Should add cache references here
                    BigInteger reversedValue = entry.getValue().multiply(clientRandomDatasetMap.get(entry.getKey()).modInverse(modulus)).mod(modulus);
                    localClientReversedDatasetMap.put(entry.getKey(), reversedValue);
                }
                return localClientReversedDatasetMap;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<Map<Long, BigInteger>> ft : futureTaskList) {
            try {
                clientReversedDatasetMap.putAll(ft.get());
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }
    }

    @Override
    public Set<String> computePsi(){
        log.debug("Called loadServerDataset");
        computeReversedMap();
        Set<String> psi = new HashSet<>();
        List<Map<Long, BigInteger>> reversedMapPartition = PartitionHelper.partitionMap(clientReversedDatasetMap, threads);
        List<FutureTask<Set<String>>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, BigInteger> partition : reversedMapPartition){
            FutureTask<Set<String>> futureTask = new FutureTask<>(() -> {
                Set<String> partitionPsiSet = new HashSet<>();
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()){
                    // Should add cache references here
                    if(serverEncryptedDataset.contains(entry.getValue()))
                        partitionPsiSet.add(CustomTypeConverter.convertBigIntegerToString(clientClearDatasetMap.get(entry.getKey())));
                }
                return partitionPsiSet;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<Set<String>> ft : futureTaskList) {
            try {
                psi.addAll(ft.get());
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }
        return psi;
    }

    // Helper class that bundles a quartet of maps. Three <Long, BigInteger> and one <Long, String>
     static class BsMapQuartet{
        public Map<Long, BigInteger> clearMap;
        public Map<Long, BigInteger> randomMap;
        public Map<Long, BigInteger> encryptedMap;
        public Map<Long, String> encryptedMapConvertedToString;
    }
}
