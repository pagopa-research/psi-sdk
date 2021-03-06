package psi;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheProvider;
import psi.exception.PsiServerException;
import psi.exception.PsiServerInitException;
import psi.exception.UnsupportedKeySizeRuntimeException;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.model.PsiPhaseStatistics;
import psi.model.PsiServerSession;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class PsiServerEcDh extends PsiServerAbstract {

    private static final Logger log = LoggerFactory.getLogger(PsiServerEcDh.class);

    PsiServerEcDh(PsiServerSession psiServerSession, PsiCacheProvider psiCacheProvider) {
        if (!PsiAlgorithm.ECDH.getSupportedKeySize().contains(psiServerSession.getPsiAlgorithmParameter().getKeySize()))
            throw new UnsupportedKeySizeRuntimeException(PsiAlgorithm.ECDH, psiServerSession.getPsiAlgorithmParameter().getKeySize());

        this.psiServerSession = psiServerSession;
        this.statisticList = new LinkedList<>();

        if (psiCacheProvider != null) {
            this.psiCacheProvider = psiCacheProvider;
            this.keyId = CacheUtils.getKeyId(this.psiServerSession.getPsiServerKeyDescription(), psiCacheProvider);
        }
    }

    static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) {
        log.debug("Called initSession()");

        PsiServerSession psiServerSession = new PsiServerSession(psiAlgorithmParameter);

        // keys are created from scratch
        if (psiServerKeyDescription == null) {
            psiServerKeyDescription = AsymmetricKeyFactory.generateServerKeyDescription(psiAlgorithmParameter.getAlgorithm(), psiAlgorithmParameter.getKeySize());
        }
        // keys are loaded from serverKeyDescription
        else {
            if (psiServerKeyDescription.getEcPrivateD() == null)
                throw new PsiServerInitException("The field ecPrivateD in the input psiServerKeyDescription is empty");
        }
        psiServerSession.setPsiServerKeyDescription(psiServerKeyDescription);

        // if psiCacheProvider != null, enable and validate the cache
        psiServerSession.setCacheEnabled(psiCacheProvider != null);

        return psiServerSession;
    }

    @Override
    public Set<String> encryptDataset(Set<String> inputSet) {
        log.debug("Called encryptDataset()");

        validatePsiServerKeyDescription();
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.ENCRYPTION);

        BigInteger ecPrivateD = CustomTypeConverter.convertStringToBigInteger(
                this.psiServerSession.getPsiServerKeyDescription().getEcPrivateD());
        EllipticCurve ellipticCurve = new EllipticCurve(CustomTypeConverter
                .convertKeySizeToECParameterSpec(this.psiServerSession.getPsiAlgorithmParameter().getKeySize()));
        ECCurve ecCurve = ellipticCurve.getEcCurve();

        Set<String> encryptedSet = ConcurrentHashMap.newKeySet();
        List<Set<String>> partitionList = PartitionHelper.partitionSet(inputSet, this.threads);
        ExecutorService executorService = Executors.newFixedThreadPool(partitionList.size());
        for(Set<String> partition : partitionList) {
            executorService.submit(() -> {
                for(String stringValue : partition){
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(stringValue);
                    ECPoint encryptedValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if(Boolean.TRUE.equals(this.psiServerSession.getCacheEnabled())) {
                        Optional<CacheObjectEcEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, CacheObjectEcEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()){
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = EllipticCurve.multiply(ellipticCurve.mapMessage(bigIntegerValue), ecPrivateD);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (Boolean.TRUE.equals(this.psiServerSession.getCacheEnabled())) {
                            CacheUtils.putCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, new CacheObjectEcEncrypted(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    encryptedSet.add(CustomTypeConverter.convertECPointToString(encryptedValue));
                }
            });
        }
        MultithreadingHelper.awaitTermination(executorService, this.threadTimeoutSeconds, log);

        this.statisticList.add(statistics.close());
        return encryptedSet;
    }

    @Override
    public Map<Long, String> encryptDatasetMap(Map<Long, String> inputMap) {
        log.debug("Called encryptDatasetMap()");
        validatePsiServerKeyDescription();
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.DOUBLE_ENCRYPTION);



        BigInteger ecPrivateD = CustomTypeConverter.convertStringToBigInteger(
                this.psiServerSession.getPsiServerKeyDescription().getEcPrivateD());
        EllipticCurve ellipticCurve = new EllipticCurve(CustomTypeConverter
                .convertKeySizeToECParameterSpec(this.psiServerSession.getPsiAlgorithmParameter().getKeySize()));
        ECCurve ecCurve = ellipticCurve.getEcCurve();

        Map<Long, String> encryptedMap = new ConcurrentHashMap<>();
        List<Map<Long, String>> partitionList = PartitionHelper.partitionMap(inputMap, this.threads);
        ExecutorService executorService = Executors.newFixedThreadPool(partitionList.size());
        for(Map<Long, String> partition : partitionList) {
            executorService.submit(() -> {
                for(Map.Entry<Long, String> entry : partition.entrySet()){
                    BigInteger keyValue = CustomTypeConverter.convertStringToBigInteger(entry.getValue()); //This value is used only to search in cache
                    ECPoint ecPointValue = CustomTypeConverter.convertStringToECPoint(ecCurve, entry.getValue());
                    ECPoint encryptedValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if (Boolean.TRUE.equals(this.psiServerSession.getCacheEnabled())) {
                        Optional<CacheObjectEcEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, keyValue, CacheObjectEcEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()){
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = EllipticCurve.multiply(ecPointValue, ecPrivateD);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (Boolean.TRUE.equals(this.psiServerSession.getCacheEnabled())) {
                            CacheUtils.putCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, keyValue, new CacheObjectEcEncrypted(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    encryptedMap.put(entry.getKey(), CustomTypeConverter.convertECPointToString(encryptedValue));
                }
            });
        }
        MultithreadingHelper.awaitTermination(executorService, this.threadTimeoutSeconds, log);

        this.statisticList.add(statistics.close());
        return encryptedMap;
    }

    @Override
    public PsiServerKeyDescription getServerKeyDescription() {
        return this.psiServerSession.getPsiServerKeyDescription();
    }

    // Helper method used to validate the required fields of the psiServerKeyDescription for this algorithm
    private void validatePsiServerKeyDescription(){
        if(this.psiServerSession.getPsiServerKeyDescription() == null
                || this.psiServerSession.getPsiServerKeyDescription().getEcPrivateD() == null
        ) throw new PsiServerException("The fields ecPrivateD of the PsiServerKeyDescription for ECDH should not be null");
    }
}
