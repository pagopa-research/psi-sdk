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
import psi.model.PsiClientSession;
import psi.exception.PsiClientException;
import psi.utils.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

public class BsPsiClient extends PsiAbstractClient {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private static final int RANDOM_BITS = 2048;

    private final AtomicLong keyAtomicCounter;

    private final SecureRandom secureRandom;
    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, BigInteger> clientRandomDatasetMap;
    private final Map<Long, BigInteger> clientDoubleEncryptedDatasetMap;
    private final Map<Long, BigInteger> clientReversedDatasetMap;
    private final Set<BigInteger> serverEncryptedDataset;

    private final BigInteger modulus;
    private final BigInteger serverPublicKey;

    public BsPsiClient(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider){
        this.serverEncryptedDataset = ConcurrentHashMap.newKeySet();
        this.clientClearDatasetMap = new ConcurrentHashMap<>();
        this.clientRandomDatasetMap = new ConcurrentHashMap<>();
        this.clientDoubleEncryptedDatasetMap = new ConcurrentHashMap<>();
        this.clientReversedDatasetMap = new ConcurrentHashMap<>();
        this.secureRandom = new SecureRandom();
        this.statisticList = new ConcurrentLinkedQueue<>();
        this.keyAtomicCounter = new AtomicLong(0);

        // keys are set from the psiClientSession
        if(psiClientKeyDescription == null) {
            this.modulus = CustomTypeConverter.convertStringToBigInteger(psiClientSession.getModulus());
            this.serverPublicKey = CustomTypeConverter.convertStringToBigInteger(psiClientSession.getServerPublicKey());
        }
        // keys are loaded from psiClientKeyDescription, but should still match those of the psiClientSession
        else{
            if(psiClientKeyDescription.getModulus() == null || psiClientKeyDescription.getServerPublicKey() == null)
                throw new PsiClientException("The fields modulus and serverPublicKey in the input psiClientKeyDescription cannot be null");
            if(!psiClientSession.getModulus().equals(psiClientKeyDescription.getModulus()) || !psiClientSession.getServerPublicKey().equals(psiClientKeyDescription.getServerPublicKey()))
                throw new PsiClientException("The fields modulus and/or serverPublicKey in the psiClientKeyDescription does not match those in the psiClientSession");
            this.modulus = CustomTypeConverter.convertStringToBigInteger(psiClientKeyDescription.getModulus());
            this.serverPublicKey = CustomTypeConverter.convertStringToBigInteger(psiClientKeyDescription.getServerPublicKey());
        }

        // TODO: check whether keys are valid wrt each other. Needed both when using the clientKeyDescription and when only using the psiClientSession

        // If psiCacheProvider != null, setup and validate the cache
        if(psiCacheProvider == null)
            this.cacheEnabled = false;
        else{
            this.keyId = PsiCacheUtils.getKeyId(getClientKeyDescription(), psiCacheProvider);
            this.cacheEnabled = true;
            this.psiCacheProvider = psiCacheProvider;
        }
    }

    @Override
    public Map<Long, String> loadAndEncryptClientDataset(Set<String> clearClientDataset) {
        log.debug("Called loadAndEncryptClientDataset");
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.ENCRYPTION);

        List<Set<String>> clientDatasetPartitions = PartitionHelper.partitionSet(clearClientDataset, this.threads);
        Map<Long, String> clientEncryptedDatasetMapConvertedToString = new ConcurrentHashMap<>();

        ExecutorService executorService = Executors.newFixedThreadPool(clientDatasetPartitions.size());
        for(Set<String> partition : clientDatasetPartitions) {
            executorService.submit(() -> {
                HashFactory hashFactory = new HashFactory(modulus);

                for(String value : partition){
                    Long key = keyAtomicCounter.incrementAndGet();
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(value);
                    BigInteger encryptedValue = null;
                    BigInteger randomValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if(this.cacheEnabled) {
                        Optional<RandomEncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(keyId, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, RandomEncryptedCacheObject.class, this.psiCacheProvider);
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
                            PsiCacheUtils.putCachedObject(keyId, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, new RandomEncryptedCacheObject(randomValue, encryptedValue),this.psiCacheProvider);
                        }
                    }
                    clientClearDatasetMap.put(key, bigIntegerValue);
                    clientRandomDatasetMap.put(key, randomValue);
                    clientEncryptedDatasetMapConvertedToString.put(key, CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                 }
            });
        }

        MultithreadingUtils.awaitTermination(executorService, threadTimeoutSeconds, log);

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
    public void loadAndProcessServerDataset(Set<String> serverEncryptedDataset) {
        log.debug("Called loadServerDataset");
        this.serverEncryptedDataset.addAll(
                serverEncryptedDataset.stream().map(CustomTypeConverter::convertStringToBigInteger).collect(Collectors.toSet()));
    }

    // Loads the clientReversedDatasetMap which contains a decryption of the clientDoubleEncryptedDatasetMap entries
    private void computeReversedMap(){
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.REVERSE_MAP);

        log.debug("Called computeReversedMap");
        List<Map<Long, BigInteger>> doubleEncryptedMapPartition = PartitionHelper.partitionMap(clientDoubleEncryptedDatasetMap, threads);
        ExecutorService executorService = Executors.newFixedThreadPool(doubleEncryptedMapPartition.size());
        for(Map<Long, BigInteger> partition : doubleEncryptedMapPartition){
            executorService.submit(() -> {
                HashFactory hashFactory = new HashFactory(modulus);

                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()) {
                    BigInteger reversedValue = null;
                    if (this.cacheEnabled) {
                        //TODO: controllare se sia corretto o se è meglio usare una chiave composta con i parametri in input alla funzione sottostante
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(keyId, PsiCacheOperationType.REVERSE_VALUE, clientClearDatasetMap.get(entry.getKey()), EncryptedCacheObject.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            reversedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    if (reversedValue == null){
                        reversedValue = hashFactory.hash(entry.getValue().multiply(clientRandomDatasetMap.get(entry.getKey()).modInverse(modulus)).mod(modulus));
                        statistics.incrementCacheMiss();
                        if (this.cacheEnabled) {
                            PsiCacheUtils.putCachedObject(keyId, PsiCacheOperationType.REVERSE_VALUE, clientClearDatasetMap.get(entry.getKey()), new EncryptedCacheObject(reversedValue), this.psiCacheProvider); //TODO, come sopra
                        }
                    }
                    clientReversedDatasetMap.put(entry.getKey(), reversedValue);
                }
            });
        }

        MultithreadingUtils.awaitTermination(executorService, threadTimeoutSeconds, log);

        statisticList.add(statistics.close());
    }

    @Override
    public Set<String> computePsi(){
        log.debug("Called loadServerDataset");

        computeReversedMap();
        Set<String> psi = ConcurrentHashMap.newKeySet();
        List<Map<Long, BigInteger>> reversedMapPartition = PartitionHelper.partitionMap(clientReversedDatasetMap, threads);
        ExecutorService executorService = Executors.newFixedThreadPool(reversedMapPartition.size());
        for(Map<Long, BigInteger> partition : reversedMapPartition){
            executorService.submit(() -> {
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()){
                    if(serverEncryptedDataset.contains(entry.getValue()))
                        psi.add(CustomTypeConverter.convertBigIntegerToString(clientClearDatasetMap.get(entry.getKey())));
                }
            });
        }

        MultithreadingUtils.awaitTermination(executorService, threadTimeoutSeconds, log);

        return psi;
    }

    @Override
    public PsiClientKeyDescription getClientKeyDescription() {
        return PsiClientKeyDescriptionFactory.createBsClientKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(this.serverPublicKey),
                CustomTypeConverter.convertBigIntegerToString(this.modulus));
    }
}
