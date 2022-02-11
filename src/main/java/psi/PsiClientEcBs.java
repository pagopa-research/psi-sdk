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
import java.util.stream.Collectors;

class PsiClientEcBs extends PsiClientAbstract {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final AtomicLong keyAtomicCounter;

    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, ECPoint> clientRandomDatasetMap;
    private final Map<Long, ECPoint> clientDoubleEncryptedDatasetMap;
    private final Map<Long, ECPoint> clientReversedDatasetMap;
    private final Set<ECPoint> serverEncryptedDataset;

    private final ECPoint serverPublicQ;
    private final ECCurve ecCurve;
    private final EllipticCurve ellipticCurve;

    PsiClientEcBs(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) {

        this.serverEncryptedDataset = ConcurrentHashMap.newKeySet();
        this.clientClearDatasetMap = new ConcurrentHashMap<>();
        this.clientRandomDatasetMap = new ConcurrentHashMap<>();
        this.clientDoubleEncryptedDatasetMap = new ConcurrentHashMap<>();
        this.clientReversedDatasetMap = new ConcurrentHashMap<>();
        this.statisticList = new ConcurrentLinkedQueue<>();
        this.keyAtomicCounter = new AtomicLong(0);

        ECParameterSpec ecSpec = CustomTypeConverter.convertKeySizeToECParameterSpec(psiClientSession.getPsiAlgorithmParameter().getKeySize());
        this.serverPublicQ = CustomTypeConverter.convertStringToECPoint(ecSpec.getCurve(), psiClientSession.getEcServerPublicQ());
        this.ellipticCurve = new EllipticCurve(ecSpec);
        this.ecCurve = ecSpec.getCurve();

        // keys are set from the psiClientSession
        if(psiClientKeyDescription != null) {
            if(psiClientKeyDescription.getEcServerPublicQ() == null)
                throw new PsiClientException("The field ecServerPublicQ in the input psiClientKeyDescription cannot be null");
            if(!psiClientSession.getEcServerPublicQ().equals(psiClientKeyDescription.getEcServerPublicQ()))
                throw new PsiClientException("The field ecServerPublicQ in the psiClientKeyDescription does not match the one in the psiClientSession");
        }

        // TODO: check whether keys are valid wrt each other. Needed both when using the clientKeyDescription and when only using the psiClientSession
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

                for(String value : partition){
                    Long key = keyAtomicCounter.incrementAndGet();
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(value);
                    ECPoint encryptedValue = null;
                    ECPoint randomValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if(this.cacheEnabled) {
                        Optional<CacheObjectEcRandomEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(keyId, CacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, CacheObjectEcRandomEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            randomValue = encryptedCacheObjectOptional.get().getRandomValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        EllipticCurve.EncryptedRandomValue encryptedRandomValue = this.ellipticCurve.generateEncryptedRandomValue(bigIntegerValue, this.serverPublicQ);
                        encryptedValue = encryptedRandomValue.getEncrypted();
                        randomValue = encryptedRandomValue.getRandom();
                        statistics.incrementCacheMiss();
                        if(this.cacheEnabled) {
                            CacheUtils.putCachedObject(keyId, CacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, new CacheObjectEcRandomEncrypted(randomValue, encryptedValue),this.psiCacheProvider);
                        }
                    }
                    clientClearDatasetMap.put(key, bigIntegerValue);
                    clientRandomDatasetMap.put(key, randomValue);
                    clientEncryptedDatasetMapConvertedToString.put(key, CustomTypeConverter.convertECPointToString(encryptedValue));
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
            this.clientDoubleEncryptedDatasetMap.put(entry.getKey(), CustomTypeConverter.convertStringToECPoint(this.ecCurve,entry.getValue()));
        }
    }

    @Override
    public void loadAndProcessServerDataset(Set<String> serverEncryptedDataset) {
        log.debug("Called loadServerDataset");
        this.serverEncryptedDataset.addAll(
                serverEncryptedDataset.stream().map(x -> CustomTypeConverter.convertStringToECPoint(this.ecCurve, x)).collect(Collectors.toSet()));
    }

    // Loads the clientReversedDatasetMap which contains a decryption of the clientDoubleEncryptedDatasetMap entries
    private void computeReversedMap(){
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.REVERSE_MAP);

        log.debug("Called computeReversedMap");
        List<Map<Long, ECPoint>> doubleEncryptedMapPartition = PartitionHelper.partitionMap(clientDoubleEncryptedDatasetMap, threads);
        ExecutorService executorService = Executors.newFixedThreadPool(doubleEncryptedMapPartition.size());
        for(Map<Long, ECPoint> partition : doubleEncryptedMapPartition){
            executorService.submit(() -> {

                for(Map.Entry<Long, ECPoint> entry : partition.entrySet()) {
                    ECPoint randomValue = clientRandomDatasetMap.get(entry.getKey());
                    ECPoint reversedValue = null;
                    BigInteger cacheKeyValue = null; // Used as key value during caching operations
                    if (this.cacheEnabled) {
                        cacheKeyValue = concatEcPoints(entry.getValue(), randomValue);
                        Optional<CacheObjectEcEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(keyId, CacheOperationType.REVERSE_VALUE, cacheKeyValue, CacheObjectEcEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            reversedValue = encryptedCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    if (reversedValue == null){
                        reversedValue = EllipticCurve.sub(entry.getValue(), randomValue);
                        statistics.incrementCacheMiss();
                        if (this.cacheEnabled) {
                            CacheUtils.putCachedObject(keyId, CacheOperationType.REVERSE_VALUE, cacheKeyValue, new CacheObjectEcEncrypted(reversedValue), this.psiCacheProvider);
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
        List<Map<Long, ECPoint>> reversedMapPartition = PartitionHelper.partitionMap(clientReversedDatasetMap, threads);
        ExecutorService executorService = Executors.newFixedThreadPool(reversedMapPartition.size());
        for(Map<Long, ECPoint> partition : reversedMapPartition){
            executorService.submit(() -> {
                for(Map.Entry<Long, ECPoint> entry : partition.entrySet()){
                    if(serverEncryptedDataset.contains(entry.getValue()))
                        psi.add(CustomTypeConverter.convertBigIntegerToString(clientClearDatasetMap.get(entry.getKey())));
                }
            });
        }

        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

        return psi;
    }

    private static BigInteger concatEcPoints(ECPoint point1, ECPoint point2){
        byte [] array1 = point1.getEncoded(true);
        byte [] array2 = point2 .getEncoded(true);

        byte[] result = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, result, 0, array1.length);
        System.arraycopy(array2, 0, result, array1.length, array1.length);

        return new BigInteger(result);
    }

    @Override
    public PsiClientKeyDescription getClientKeyDescription() {
        return PsiClientKeyDescriptionFactory.createEcBsClientKeyDescription(this.serverPublicQ);
    }

}
