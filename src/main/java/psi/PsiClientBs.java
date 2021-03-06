package psi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheProvider;
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

    private static final Logger log = LoggerFactory.getLogger(PsiClientBs.class);

    private static final int RANDOM_BITS = 2048;
    private final SecureRandom secureRandom;

    // Collections used to store working element sets
    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, BigInteger> clientRandomDatasetMap;
    private final Map<Long, BigInteger> clientDoubleEncryptedDatasetMap;
    private final Map<Long, BigInteger> clientReversedDatasetMap;
    private final Set<BigInteger> serverEncryptedDataset;

    // Variables used to perform encryption operations
    private final BigInteger modulus;
    private final BigInteger serverPublicExponent;

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
        this.serverPublicExponent = CustomTypeConverter.convertStringToBigInteger(psiClientSession.getServerPublicExponent());

        // If an external key description is provided, it should match with the values contained into psiClientSession
        if (psiClientKeyDescription != null) {
            if (psiClientKeyDescription.getModulus() == null || psiClientKeyDescription.getServerPublicExponent() == null)
                throw new PsiClientException("The fields modulus and serverPublicExponent in the input psiClientKeyDescription cannot be null");
            if (!psiClientSession.getModulus().equals(psiClientKeyDescription.getModulus()) || !psiClientSession.getServerPublicExponent().equals(psiClientKeyDescription.getServerPublicExponent()))
                throw new PsiClientException("The fields modulus and/or serverPublicExponent in the psiClientKeyDescription does not match those in the psiClientSession");
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
                HashFactory hashFactory = new HashFactory(this.modulus);

                for(String value : partition){
                    Long key = this.keyAtomicCounter.incrementAndGet();
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(value);
                    BigInteger encryptedValue = null;
                    BigInteger randomValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if(Boolean.TRUE.equals(this.cacheEnabled)) {
                        Optional<CacheObjectRandomEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(this.keyId, CacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, CacheObjectRandomEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            randomValue = encryptedCacheObjectOptional.get().getRandomValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        randomValue = new BigInteger(RANDOM_BITS, this.secureRandom).mod(this.modulus);
                        encryptedValue = randomValue.modPow(this.serverPublicExponent, this.modulus).multiply(hashFactory.hashFullDomain(bigIntegerValue)).mod(this.modulus);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if(Boolean.TRUE.equals(this.cacheEnabled)) {
                            CacheUtils.putCachedObject(this.keyId, CacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, new CacheObjectRandomEncrypted(randomValue, encryptedValue),this.psiCacheProvider);
                        }
                    }
                    this.clientClearDatasetMap.put(key, bigIntegerValue);
                    this.clientRandomDatasetMap.put(key, randomValue);
                    clientEncryptedDatasetMapConvertedToString.put(key, CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                 }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, this.threadTimeoutSeconds, log);

        this.statisticList.add(statistics.close());
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
        List<Map<Long, BigInteger>> doubleEncryptedMapPartition = PartitionHelper.partitionMap(this.clientDoubleEncryptedDatasetMap, this.threads);
        ExecutorService executorService = Executors.newFixedThreadPool(doubleEncryptedMapPartition.size());
        for(Map<Long, BigInteger> partition : doubleEncryptedMapPartition){
            executorService.submit(() -> {
                HashFactory hashFactory = new HashFactory(this.modulus);
                BigInteger cacheKeyValue = null; // Used as key value during caching operations
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()) {
                    BigInteger randomValue = this.clientRandomDatasetMap.get(entry.getKey());
                    BigInteger reversedValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if (Boolean.TRUE.equals(this.cacheEnabled)) {
                        cacheKeyValue = concatBigIntegers(entry.getValue(), randomValue);
                        Optional<CacheObjectEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(this.keyId, CacheOperationType.REVERSE_VALUE, cacheKeyValue, CacheObjectEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            reversedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (reversedValue == null) {
                        reversedValue = hashFactory.hash(entry.getValue().multiply(randomValue.modInverse(this.modulus)).mod(this.modulus));
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (Boolean.TRUE.equals(this.cacheEnabled)) {
                            CacheUtils.putCachedObject(this.keyId, CacheOperationType.REVERSE_VALUE, cacheKeyValue, new CacheObjectEncrypted(reversedValue), this.psiCacheProvider);
                        }
                    }
                    this.clientReversedDatasetMap.put(entry.getKey(), reversedValue);
                }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, this.threadTimeoutSeconds, log);

        this.statisticList.add(statistics.close());
    }

    @Override
    public Set<String> computePsi(){
        log.debug("Called loadServerDataset");

        computeReversedMap();
        Set<String> psi = ConcurrentHashMap.newKeySet();
        List<Map<Long, BigInteger>> reversedMapPartition = PartitionHelper.partitionMap(this.clientReversedDatasetMap, this.threads);
        ExecutorService executorService = Executors.newFixedThreadPool(reversedMapPartition.size());
        for(Map<Long, BigInteger> partition : reversedMapPartition){
            executorService.submit(() -> {
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()){
                    if(this.serverEncryptedDataset.contains(entry.getValue()))
                        psi.add(CustomTypeConverter.convertBigIntegerToString(this.clientClearDatasetMap.get(entry.getKey())));
                }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, this.threadTimeoutSeconds, log);

        return psi;
    }

    private static BigInteger concatBigIntegers(BigInteger bigInteger1, BigInteger bigInteger2){
        byte [] array1 = bigInteger1.toByteArray();
        byte [] array2 = bigInteger2.toByteArray();

        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array2.length);

        return new BigInteger(result);
    }

    @Override
    public PsiClientKeyDescription getClientKeyDescription() {
        return PsiClientKeyDescriptionFactory.createBsClientKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(this.serverPublicExponent),
                CustomTypeConverter.convertBigIntegerToString(this.modulus));
    }
}
