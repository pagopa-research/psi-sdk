package psi;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
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

class PsiClientEcDh extends PsiClientAbstract {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final AtomicLong keyAtomicCounter;

    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, ECPoint> clientDoubleEncryptedDatasetMap;

    private final Set<ECPoint> serverDoubleEncryptedDataset;

    private final BigInteger clientPrivateD;
    private final ECCurve ecCurve;
    private final EllipticCurve ellipticCurve;

    PsiClientEcDh(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) {

        this.serverDoubleEncryptedDataset = ConcurrentHashMap.newKeySet();
        this.clientClearDatasetMap = new ConcurrentHashMap<>();
        this.clientDoubleEncryptedDatasetMap = new ConcurrentHashMap<>();

        this.statisticList = new ConcurrentLinkedQueue<>();
        this.keyAtomicCounter = new AtomicLong(0);


        ECParameterSpec ecSpec = CustomTypeConverter.convertKeySizeToECParameterSpec(psiClientSession.getPsiAlgorithmParameter().getKeySize());
        this.ellipticCurve = new EllipticCurve(ecSpec);
        this.ecCurve = ecSpec.getCurve();

        // keys are set from the psiClientSession
        if (psiClientKeyDescription == null) {
            AsymmetricKeyFactory.AsymmetricEcKey asymmetricEcKey = AsymmetricKeyFactory.generateEcDhKeyFromECParameterSpec(ecSpec);
            this.clientPrivateD = asymmetricEcKey.privateD;
        }
        // keys are loaded from psiClientKeyDescription, but should still match those of the psiClientSession
        else {
            if (psiClientKeyDescription.getEcClientPrivateD() == null)
                throw new PsiClientException("The field ecClientPrivateD in the input psiClientKeyDescription cannot be null");
            this.clientPrivateD = CustomTypeConverter.convertStringToBigInteger(psiClientKeyDescription.getEcClientPrivateD());
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

                for (String stringValue : partition) {
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(stringValue);
                    ECPoint encryptedValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if (this.cacheEnabled) {
                        Optional<CacheObjectEcEncrypted> encryptedEcCacheObjectOptional = CacheUtils.getCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, CacheObjectEcEncrypted.class, this.psiCacheProvider);
                        if (encryptedEcCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedEcCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = EllipticCurve.multiply(ellipticCurve.mapMessage(bigIntegerValue), this.clientPrivateD);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (this.cacheEnabled) {
                            CacheUtils.putCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, new CacheObjectEcEncrypted(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    Long key = keyAtomicCounter.incrementAndGet();
                    clientClearDatasetMap.put(key, bigIntegerValue);
                    clientEncryptedDatasetMapConvertedToString.put(key, CustomTypeConverter.convertECPointToString(encryptedValue));
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
            this.clientDoubleEncryptedDatasetMap.put(entry.getKey(), CustomTypeConverter.convertStringToECPoint(this.ecCurve,entry.getValue()));
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
                    BigInteger keyValue = CustomTypeConverter.convertStringToBigInteger(serverEncryptedEntry); //This value is used only to search in cache
                    ECPoint ecPointValue = CustomTypeConverter.convertStringToECPoint(ecCurve, serverEncryptedEntry);
                    ECPoint encryptedValue = null;
                    if (this.cacheEnabled) {
                        Optional<CacheObjectEcEncrypted> encryptedEcCacheObjectOptional = CacheUtils.getCachedObject(keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, keyValue, CacheObjectEcEncrypted.class, this.psiCacheProvider);
                        if (encryptedEcCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedEcCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = EllipticCurve.multiply(ecPointValue, this.clientPrivateD);
                        statistics.incrementCacheMiss();
                        if (this.cacheEnabled) {
                            CacheUtils.putCachedObject(keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, keyValue, new CacheObjectEcEncrypted(encryptedValue), this.psiCacheProvider);
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
        List<Map<Long, ECPoint>> reversedMapPartition = PartitionHelper.partitionMap(clientDoubleEncryptedDatasetMap, threads);
        ExecutorService executorService = Executors.newFixedThreadPool(reversedMapPartition.size());
        for (Map<Long, ECPoint> partition : reversedMapPartition) {
            executorService.submit(() -> {
                for (Map.Entry<Long, ECPoint> entry : partition.entrySet()) {
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
        return PsiClientKeyDescriptionFactory.createEcDhClientKeyDescription(this.clientPrivateD);
    }

}
