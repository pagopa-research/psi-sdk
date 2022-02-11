package psi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheProvider;
import psi.exception.PsiClientException;
import psi.model.PsiClientSession;
import psi.model.PsiPhaseStatistics;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

class PsiClientDh extends PsiClientAbstract {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final AtomicLong keyAtomicCounter;

    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, BigInteger> clientDoubleEncryptedDatasetMap;

    private final Set<BigInteger> serverDoubleEncryptedDataset;

    private final BigInteger modulus;
    private final BigInteger clientPrivateExponent;

    PsiClientDh(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) {

        this.serverDoubleEncryptedDataset = ConcurrentHashMap.newKeySet();
        this.clientClearDatasetMap = new ConcurrentHashMap<>();
        this.clientDoubleEncryptedDatasetMap = new ConcurrentHashMap<>();

        this.statisticList = new ConcurrentLinkedQueue<>();
        this.keyAtomicCounter = new AtomicLong(0);

        this.modulus = CustomTypeConverter.convertStringToBigInteger(psiClientSession.getModulus());
        // keys are set from the psiClientSession
        if (psiClientKeyDescription == null) {
            AsymmetricKeyFactory.AsymmetricKey asymmetricKey = AsymmetricKeyFactory.generateDhKeyFromModulusAndGenerator(
                    modulus, CustomTypeConverter.convertStringToBigInteger(psiClientSession.getGenerator()));
            this.clientPrivateExponent = asymmetricKey.privateExponent;
        }
        // keys are loaded from psiClientKeyDescription, but should still match those of the psiClientSession
        else {
            if (psiClientKeyDescription.getModulus() == null || psiClientKeyDescription.getClientPrivateExponent() == null)
                throw new PsiClientException("The fields modulus and clientPrivateExponent in the input psiClientKeyDescription cannot be null");
            if (!psiClientSession.getModulus().equals(psiClientKeyDescription.getModulus()))
                throw new PsiClientException("The field modulus in the psiClientKeyDescription does not match those in the psiClientSession");
            this.clientPrivateExponent = CustomTypeConverter.convertStringToBigInteger(psiClientKeyDescription.getClientPrivateExponent());
        }

        // TODO: check whether keys are valid wrt each other. Needed both when using the clientKeyDescription and when only using the psiClientSession

        // If psiCacheProvider != null, setup and validate the cache
        if (psiCacheProvider == null)
            this.cacheEnabled = false;
        else {
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
        for (Set<String> partition : clientDatasetPartitions) {
            executorService.submit(() -> {
                    HashFactory hashFactory = new HashFactory(modulus);

                    for (String stringValue : partition) {
                        BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(stringValue);
                        BigInteger encryptedValue = null;
                        // If the cache support is enabled, the result is searched in the cache
                        if (this.cacheEnabled) {
                            Optional<CacheObjectEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, CacheObjectEncrypted.class, this.psiCacheProvider);
                            if (encryptedCacheObjectOptional.isPresent()) {
                                encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                                statistics.incrementCacheHit();
                            }
                        }
                        // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                        if (encryptedValue == null) {
                            encryptedValue = hashFactory.hashFullDomain(bigIntegerValue);
                            encryptedValue = encryptedValue.modPow(clientPrivateExponent, modulus);
                            statistics.incrementCacheMiss();
                            // If the cache support is enabled, the result is stored in the cache
                            if (this.cacheEnabled) {
                                CacheUtils.putCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, new CacheObjectEncrypted(encryptedValue), this.psiCacheProvider);
                            }
                        }
                        Long key = keyAtomicCounter.incrementAndGet();
                        clientClearDatasetMap.put(key, bigIntegerValue);
                        clientEncryptedDatasetMapConvertedToString.put(key, CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                    }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

        statisticList.add(statistics.close());
        return clientEncryptedDatasetMapConvertedToString;
    }

    @Override
    public void loadDoubleEncryptedClientDataset(Map<Long, String> doubleEncryptedClientDatasetMap) {
        log.debug("Called loadDoubleEncryptedClientDataset");
        for (Map.Entry<Long, String> entry : doubleEncryptedClientDatasetMap.entrySet()) {
            this.clientDoubleEncryptedDatasetMap.put(entry.getKey(), CustomTypeConverter.convertStringToBigInteger(entry.getValue()));
        }
    }

    @Override
    public void loadAndProcessServerDataset(Set<String> serverEncryptedDataset) {
        log.debug("Called loadServerDataset");
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.DOUBLE_ENCRYPTION);

        List<Set<String>> partitionList = PartitionHelper.partitionSet(serverEncryptedDataset, this.threads);

        ExecutorService executorService = Executors.newFixedThreadPool(partitionList.size());
        for (Set<String> partition : partitionList) {
            executorService.submit(() -> {
                for (String serverEncryptedEntry : partition) {
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(serverEncryptedEntry);
                    BigInteger encryptedValue = null;
                    if (this.cacheEnabled) {
                        Optional<CacheObjectEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, CacheObjectEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = bigIntegerValue.modPow(this.clientPrivateExponent, modulus);
                        statistics.incrementCacheMiss();
                        if (this.cacheEnabled) {
                            CacheUtils.putCachedObject(keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, new CacheObjectEncrypted(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    serverDoubleEncryptedDataset.add(encryptedValue);

                }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

        statisticList.add(statistics.close());
    }

    // Loads the clientReversedDatasetMap which contains a decryption of the clientDoubleEncryptedDatasetMap entries
    private void computeReversedMap() {
        log.debug("Called computeReversedMap");
    }

    @Override
    public Set<String> computePsi() {
        log.debug("Called loadServerDataset");
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.PSI);

        computeReversedMap();
        Set<String> psi = ConcurrentHashMap.newKeySet();
        List<Map<Long, BigInteger>> reversedMapPartition = PartitionHelper.partitionMap(clientDoubleEncryptedDatasetMap, threads);
        ExecutorService executorService = Executors.newFixedThreadPool(reversedMapPartition.size());
        for (Map<Long, BigInteger> partition : reversedMapPartition) {
            executorService.submit(() -> {
                for (Map.Entry<Long, BigInteger> entry : partition.entrySet()) {
                    if (serverDoubleEncryptedDataset.contains(entry.getValue()))
                        psi.add(CustomTypeConverter.convertBigIntegerToString(clientClearDatasetMap.get(entry.getKey())));
                }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

        statisticList.add(statistics.close());
        return psi;
    }

    @Override
    public PsiClientKeyDescription getClientKeyDescription() {
        return PsiClientKeyDescriptionFactory.createDhClientKeyDescription(this.clientPrivateExponent, this.modulus);
    }

}
