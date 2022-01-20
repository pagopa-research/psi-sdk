package psi.client.algorithm.bs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheProvider;
import psi.cache.PsiCacheUtils;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.EncryptedCacheObject;
import psi.cache.model.RandomEncryptedCacheObject;
import psi.client.PsiAbstractClient;
import psi.client.PsiClientKeyDescriptionFactory;
import psi.client.PsiClientKeyDescription;
import psi.dto.PsiSessionDTO;
import psi.exception.MismatchedCacheKeyIdException;
import psi.exception.PsiClientException;
import psi.utils.CustomTypeConverter;
import psi.utils.HashFactory;
import psi.utils.PartitionHelper;
import psi.utils.StatisticsFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicLong;

public class BsPsiClient extends PsiAbstractClient {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private static final int RANDOM_BITS = 2048;

    private final AtomicLong keyAtomicCounter;

    private final SecureRandom secureRandom;
    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, BigInteger> clientRandomDatasetMap;
    private final Map<Long, BigInteger> clientEncryptedDatasetMap;
    private final Map<Long, BigInteger> clientDoubleEncryptedDatasetMap;
    private final Map<Long, BigInteger> clientReversedDatasetMap;

    private final BigInteger modulus;
    private final BigInteger serverPublicKey;

    public BsPsiClient(PsiSessionDTO psiSessionDTO, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider){
        this.serverEncryptedDataset = new HashSet<>();
        this.clientClearDatasetMap = new HashMap<>();
        this.clientRandomDatasetMap = new HashMap<>();
        this.clientEncryptedDatasetMap = new HashMap<>();
        this.clientDoubleEncryptedDatasetMap = new HashMap<>();
        this.clientReversedDatasetMap = new HashMap<>();
        this.threads = DEFAULT_THREADS;
        this.secureRandom = new SecureRandom();
        this.keyAtomicCounter = new AtomicLong(0);
        this.statisticList = new LinkedList<>();

        // keys are set from the psiSessionDTO
        if(psiClientKeyDescription == null) {
            this.modulus = CustomTypeConverter.convertStringToBigInteger(psiSessionDTO.getModulus());
            this.serverPublicKey = CustomTypeConverter.convertStringToBigInteger(psiSessionDTO.getServerPublicKey());
        }
        // keys are loaded from bsClientKeyDescription, but should still match those of psiSessionDTO
        else{
            if(psiClientKeyDescription.getModulus() == null || psiClientKeyDescription.getServerPublicKey() == null)
                throw new PsiClientException("The fields modulus and serverPrivateKey in the input bsClientKeyDescription cannot be null");
            if(!psiSessionDTO.getModulus().equals(psiClientKeyDescription.getModulus()) || !psiSessionDTO.getServerPublicKey().equals(psiClientKeyDescription.getServerPublicKey()))
                throw new PsiClientException("The fields modulus and/or serverPrivateKey in the bsClientKeyDescription does not match those in the psiSessionDTO");
            this.modulus = CustomTypeConverter.convertStringToBigInteger(psiClientKeyDescription.getModulus());
            this.serverPublicKey = CustomTypeConverter.convertStringToBigInteger(psiClientKeyDescription.getServerPublicKey());
        }

        // TODO: check whether keys are valid wrt each other. Needed both when using the clientKeyDescription and when only using the psiSessionDTO

        // If psiCacheProvider != null, setup and validate the cache
        if(psiCacheProvider == null)
            this.cacheEnabled = false;
        else{
            this.keyId = PsiCacheUtils.getKeyId(psiClientKeyDescription, psiCacheProvider);
            this.cacheEnabled = true;
            this.encryptionCacheProvider = psiCacheProvider;
        }
    }

    @Override
    public Map<Long, String> loadAndEncryptClientDataset(Set<String> clearClientDataset) {
        log.debug("Called loadAndEncryptClientDataset");
        StatisticsFactory statistics = new StatisticsFactory(StatisticsFactory.PsiPhase.ENCRYPTION);

        List<Set<String>> clientDatasetPartitions = PartitionHelper.partitionSet(clearClientDataset, this.threads);
        Map<Long, String> clientEncryptedDatasetMapConvertedToString = new HashMap<>();

        List<FutureTask<BsMapQuartet>> futureTaskList = new ArrayList<>(threads);
        for(Set<String> partition : clientDatasetPartitions) {
            FutureTask<BsMapQuartet> futureTask = new FutureTask<>(() -> {
                Map<Long, BigInteger> localClientClearDatasetMap = new HashMap<>();
                Map<Long, BigInteger> localClientRandomDatasetMap = new HashMap<>();
                Map<Long, BigInteger> localClientEncryptedDatasetMap = new HashMap<>();
                Map<Long, String> localClientEncryptedDatasetMapConvertedToString = new HashMap<>();
                HashFactory hashFactory = new HashFactory(modulus);

                for(String value : partition){
                    Long key = keyAtomicCounter.incrementAndGet();
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(value);
                    BigInteger encryptedValue = null;
                    BigInteger randomValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if(this.cacheEnabled) {
                        Optional<RandomEncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(keyId, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, RandomEncryptedCacheObject.class, this.encryptionCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            randomValue = encryptedCacheObjectOptional.get().getRandomValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        randomValue = new BigInteger(RANDOM_BITS, this.secureRandom).mod(modulus);
                        encryptedValue = randomValue.modPow(serverPublicKey, modulus).multiply(hashFactory.hashFullDomain(bigIntegerValue)).mod(modulus);
                        statistics.incrementCacheMiss();
                        if(this.cacheEnabled) {
                            PsiCacheUtils.putCachedObject(keyId, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, new RandomEncryptedCacheObject(randomValue, encryptedValue),this.encryptionCacheProvider);
                        }
                    }
                     localClientClearDatasetMap.put(key, bigIntegerValue);
                     localClientRandomDatasetMap.put(key, randomValue);
                     localClientEncryptedDatasetMap.put(key, encryptedValue);
                     localClientEncryptedDatasetMapConvertedToString.put(key, CustomTypeConverter.convertBigIntegerToString(encryptedValue));
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

        statisticList.add(statistics.close());
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
        StatisticsFactory statistics = new StatisticsFactory(StatisticsFactory.PsiPhase.REVERSE_MAP);

        log.debug("Called computeReversedMap");
        List<Map<Long, BigInteger>> doubleEncryptedMapPartition = PartitionHelper.partitionMap(clientDoubleEncryptedDatasetMap, threads);
        List<FutureTask<Map<Long, BigInteger>>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, BigInteger> partition : doubleEncryptedMapPartition){
            FutureTask<Map<Long, BigInteger>> futureTask = new FutureTask<>(() -> {
                HashFactory hashFactory = new HashFactory(modulus);
                Map<Long, BigInteger> localClientReversedDatasetMap = new HashMap<>();
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()) {
                    BigInteger reversedValue = null;
                    if (this.cacheEnabled) {
                        //TODO: controllare se sia corretto o se è meglio usare una chiave composta con i parametri in input alla funzione sottostante
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(keyId, PsiCacheOperationType.REVERSE_VALUE, clientClearDatasetMap.get(entry.getKey()), EncryptedCacheObject.class, this.encryptionCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            reversedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    if (reversedValue == null){
                        reversedValue = hashFactory.hash(entry.getValue().multiply(clientRandomDatasetMap.get(entry.getKey()).modInverse(modulus)).mod(modulus));
                        statistics.incrementCacheMiss();
                        if (this.cacheEnabled) {
                            PsiCacheUtils.putCachedObject(keyId, PsiCacheOperationType.REVERSE_VALUE, clientClearDatasetMap.get(entry.getKey()), new EncryptedCacheObject(reversedValue), this.encryptionCacheProvider); //TODO, come sopra
                        }
                    }
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
        statisticList.add(statistics.close());
    }

    @Override
    public Set<String> computePsi(){
        log.debug("Called loadServerDataset");
        StatisticsFactory statistics = new StatisticsFactory(StatisticsFactory.PsiPhase.PSI);

        computeReversedMap();
        Set<String> psi = new HashSet<>();
        List<Map<Long, BigInteger>> reversedMapPartition = PartitionHelper.partitionMap(clientReversedDatasetMap, threads);
        List<FutureTask<Set<String>>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, BigInteger> partition : reversedMapPartition){
            FutureTask<Set<String>> futureTask = new FutureTask<>(() -> {
                Set<String> partitionPsiSet = new HashSet<>();
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()){
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

    @Override
    public PsiClientKeyDescription getClientKeyDescription() {
        return PsiClientKeyDescriptionFactory.createBsClientKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(this.serverPublicKey),
                CustomTypeConverter.convertBigIntegerToString(this.modulus));
    }

    // Helper class that bundles a quartet of maps. Three <Long, BigInteger> and one <Long, String>
     static class BsMapQuartet{
        public Map<Long, BigInteger> clearMap;
        public Map<Long, BigInteger> randomMap;
        public Map<Long, BigInteger> encryptedMap;
        public Map<Long, String> encryptedMapConvertedToString;
    }
}
