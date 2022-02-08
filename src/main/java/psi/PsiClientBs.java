package psi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheProvider;
import psi.client.PsiClientKeyDescription;
import psi.client.PsiClientKeyDescriptionFactory;
import psi.exception.PsiClientException;
import psi.model.PsiClientSession;
import psi.model.PsiPhaseStatistics;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

class PsiClientBs extends PsiClientAbstract {

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

    PsiClientBs(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) {

        this.serverEncryptedDataset = ConcurrentHashMap.newKeySet();
        this.clientClearDatasetMap = new ConcurrentHashMap<>();
        this.clientRandomDatasetMap = new ConcurrentHashMap<>();
        this.clientDoubleEncryptedDatasetMap = new ConcurrentHashMap<>();
        this.clientReversedDatasetMap = new ConcurrentHashMap<>();
        this.secureRandom = new SecureRandom();
        this.statisticList = new ConcurrentLinkedQueue<>();
        this.keyAtomicCounter = new AtomicLong(0);

        this.modulus = CustomTypeConverter.convertStringToBigInteger(psiClientSession.getModulus());
        this.serverPublicKey = CustomTypeConverter.convertStringToBigInteger(psiClientSession.getServerPublicKey());

        // If an external key is provided, it should be equivalent to the key read from the psiClientSession
        if (psiClientKeyDescription != null) {
            if(psiClientKeyDescription.getModulus() == null || psiClientKeyDescription.getServerPublicKey() == null)
                throw new PsiClientException("The fields modulus and serverPublicKey in the input psiClientKeyDescription cannot be null");
            if(!psiClientSession.getModulus().equals(psiClientKeyDescription.getModulus()) || !psiClientSession.getServerPublicKey().equals(psiClientKeyDescription.getServerPublicKey()))
                throw new PsiClientException("The fields modulus and/or serverPublicKey in the psiClientKeyDescription does not match those in the psiClientSession");
        }

        // If psiCacheProvider != null, setup and validate the cache
        if(psiCacheProvider == null)
            this.cacheEnabled = false;
        else{
            this.keyId = CacheUtils.getKeyId(getClientKeyDescription(), psiCacheProvider);
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
                        Optional<CacheObjectRandomEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(keyId, CacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, CacheObjectRandomEncrypted.class, this.psiCacheProvider);
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
                            CacheUtils.putCachedObject(keyId, CacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, new CacheObjectRandomEncrypted(randomValue, encryptedValue),this.psiCacheProvider);
                        }
                    }
                    clientClearDatasetMap.put(key, bigIntegerValue);
                    clientRandomDatasetMap.put(key, randomValue);
                    clientEncryptedDatasetMapConvertedToString.put(key, CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                 }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

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
                BigInteger cacheKeyValue = null; // Used as key value during caching operations
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()) {
                    BigInteger randomValue = clientRandomDatasetMap.get(entry.getKey());
                    BigInteger reversedValue = null;
                    if (this.cacheEnabled) {
                        cacheKeyValue = concatBigIntegers(entry.getValue(), randomValue);
                        Optional<CacheObjectEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(keyId, CacheOperationType.REVERSE_VALUE, cacheKeyValue, CacheObjectEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            reversedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    if (reversedValue == null){
                        reversedValue = hashFactory.hash(entry.getValue().multiply(randomValue.modInverse(modulus)).mod(modulus));
                        statistics.incrementCacheMiss();
                        if (this.cacheEnabled) {
                            CacheUtils.putCachedObject(keyId, CacheOperationType.REVERSE_VALUE, cacheKeyValue, new CacheObjectEncrypted(reversedValue), this.psiCacheProvider); //TODO, come sopra
                        }
                    }
                    clientReversedDatasetMap.put(entry.getKey(), reversedValue);
                }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

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

        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

        return psi;
    }

    private static BigInteger concatBigIntegers(BigInteger bigInteger1, BigInteger bigInteger2){
        byte [] array1 = bigInteger1.toByteArray();
        byte [] array2 = bigInteger1.toByteArray();

        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array1.length);

        return new BigInteger(result);
    }

    @Override
    public PsiClientKeyDescription getClientKeyDescription() {
        return PsiClientKeyDescriptionFactory.createBsClientKeyDescription(this.serverPublicKey,this.modulus);
    }
}
