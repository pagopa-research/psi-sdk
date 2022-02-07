package psi.client.algorithm.ecbs;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheProvider;
import psi.cache.PsiCacheUtils;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.EncryptedEcCacheObject;
import psi.cache.model.RandomEncryptedEcCacheObject;
import psi.client.PsiAbstractClient;
import psi.client.PsiClientKeyDescription;
import psi.client.PsiClientKeyDescriptionFactory;
import psi.exception.PsiClientException;
import psi.exception.UnsupportedKeySizeException;
import psi.model.EllipticCurve;
import psi.model.PsiAlgorithm;
import psi.model.PsiClientSession;
import psi.model.PsiPhaseStatistics;
import psi.utils.CustomTypeConverter;
import psi.utils.MultithreadingHelper;
import psi.utils.PartitionHelper;

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

public class EcBsPsiClient extends PsiAbstractClient {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final AtomicLong keyAtomicCounter;

    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, ECPoint> clientRandomDatasetMap;
    private final Map<Long, ECPoint> clientDoubleEncryptedDatasetMap;
    private final Map<Long, ECPoint> clientReversedDatasetMap;
    private final Set<ECPoint> serverEncryptedDataset;

    private final ECPoint serverPublicKey;
    private final ECCurve ecCurve;
    private final EllipticCurve ellipticCurve;

    public EcBsPsiClient(PsiClientSession psiClientSession, PsiClientKeyDescription psiClientKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        if (!PsiAlgorithm.ECBS.getSupportedKeySize().contains(psiClientSession.getPsiAlgorithmParameter().getKeySize()))
            throw new UnsupportedKeySizeException(PsiAlgorithm.ECBS, psiClientSession.getPsiAlgorithmParameter().getKeySize());

        this.serverEncryptedDataset = ConcurrentHashMap.newKeySet();
        this.clientClearDatasetMap = new ConcurrentHashMap<>();
        this.clientRandomDatasetMap = new ConcurrentHashMap<>();
        this.clientDoubleEncryptedDatasetMap = new ConcurrentHashMap<>();
        this.clientReversedDatasetMap = new ConcurrentHashMap<>();
        this.statisticList = new ConcurrentLinkedQueue<>();
        this.keyAtomicCounter = new AtomicLong(0);

        ECParameterSpec ecSpec = CustomTypeConverter.convertStringToECParameterSpec(psiClientSession.getEcSpecName());
        this.serverPublicKey = CustomTypeConverter.convertStringToECPoint(ecSpec.getCurve(), psiClientSession.getEcServerPublicKey());
        this.ellipticCurve = new EllipticCurve(ecSpec);
        this.ecCurve = ecSpec.getCurve();

        // keys are set from the psiClientSession
        if(psiClientKeyDescription != null) {
            if(psiClientKeyDescription.getEcSpecName() == null || psiClientKeyDescription.getEcServerPublicKey() == null)
                throw new PsiClientException("The fields ecSpec and ecServerPublicKey in the input psiClientKeyDescription cannot be null");
            if(!psiClientSession.getEcSpecName().equals(psiClientKeyDescription.getEcSpecName()) ||
                    !psiClientSession.getEcServerPublicKey().equals(psiClientKeyDescription.getEcServerPublicKey()))
                throw new PsiClientException("The fields ecSpec and/or ecServerPublicKey in the psiClientKeyDescription does not match those in the psiClientSession");
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

                for(String value : partition){
                    Long key = keyAtomicCounter.incrementAndGet();
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(value);
                    ECPoint encryptedValue = null;
                    ECPoint randomValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if(this.cacheEnabled) {
                        Optional<RandomEncryptedEcCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(keyId, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, RandomEncryptedEcCacheObject.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            randomValue = encryptedCacheObjectOptional.get().getRandomValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        EllipticCurve.EncryptedRandomValue encryptedRandomValue = this.ellipticCurve.generateEncryptedRandomValue(bigIntegerValue, this.serverPublicKey);
                        encryptedValue = encryptedRandomValue.getEncrypted();
                        randomValue = encryptedRandomValue.getRandom();
                        statistics.incrementCacheMiss();
                        if(this.cacheEnabled) {
                            PsiCacheUtils.putCachedObject(keyId, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, new RandomEncryptedEcCacheObject(randomValue, encryptedValue),this.psiCacheProvider);
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
                    ECPoint reversedValue = null;
                    if (this.cacheEnabled) {
                        //TODO: controllare se sia corretto o se è meglio usare una chiave composta con i parametri in input alla funzione sottostante
                        Optional<EncryptedEcCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(keyId, PsiCacheOperationType.REVERSE_VALUE, clientClearDatasetMap.get(entry.getKey()), EncryptedEcCacheObject.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            reversedValue = encryptedCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    if (reversedValue == null){
                        reversedValue = EllipticCurve.sub(entry.getValue(), clientRandomDatasetMap.get(entry.getKey()));
                        statistics.incrementCacheMiss();
                        if (this.cacheEnabled) {
                            PsiCacheUtils.putCachedObject(keyId, PsiCacheOperationType.REVERSE_VALUE, clientClearDatasetMap.get(entry.getKey()), new EncryptedEcCacheObject(reversedValue), this.psiCacheProvider); //TODO, come sopra
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

    @Override
    public PsiClientKeyDescription getClientKeyDescription() {
        return PsiClientKeyDescriptionFactory.createEcBsClientKeyDescription(this.serverPublicKey, this.ellipticCurve.getEcParameterSpec());
    }
}
