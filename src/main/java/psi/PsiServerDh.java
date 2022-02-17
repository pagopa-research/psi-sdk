package psi;

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

class PsiServerDh extends PsiServerAbstract {

    private static final Logger log = LoggerFactory.getLogger(PsiServerDh.class);

    PsiServerDh(PsiServerSession psiServerSession, PsiCacheProvider psiCacheProvider) {
        if (!PsiAlgorithm.DH.getSupportedKeySize().contains(psiServerSession.getPsiAlgorithmParameter().getKeySize()))
            throw new UnsupportedKeySizeRuntimeException(PsiAlgorithm.DH, psiServerSession.getPsiAlgorithmParameter().getKeySize());

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
            if (psiServerKeyDescription.getModulus() == null || psiServerKeyDescription.getPrivateExponent() == null)
                throw new PsiServerInitException("The private exponent and/or modulus passed in the input psiServerKeyDescription are either null or empty");
        }
        psiServerSession.setPsiServerKeyDescription(psiServerKeyDescription);

        // if psiCacheProvider != null, enable and validate the cache
        psiServerSession.setCacheEnabled(psiCacheProvider != null);

        return psiServerSession;
    }

    @Override
    public Set<String> encryptDataset(Set<String> inputSet) {
        log.debug("Called encryptDataset()");
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.ENCRYPTION);

        validatePsiServerKeyDescription();

        BigInteger serverPrivateExponent = CustomTypeConverter.convertStringToBigInteger(this.psiServerSession.getPsiServerKeyDescription().getPrivateExponent());
        BigInteger modulus = CustomTypeConverter.convertStringToBigInteger(this.psiServerSession.getPsiServerKeyDescription().getModulus());

        Set<String> encryptedSet = ConcurrentHashMap.newKeySet();
        List<Set<String>> partitionList = PartitionHelper.partitionSet(inputSet, this.threads);
        ExecutorService executorService = Executors.newFixedThreadPool(partitionList.size());
        for (Set<String> partition : partitionList) {
            executorService.submit(() -> {
                HashFactory hashFactory = new HashFactory(modulus);

                for (String stringValue : partition) {
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(stringValue);
                    BigInteger encryptedValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if (Boolean.TRUE.equals(this.psiServerSession.getCacheEnabled())) {
                        Optional<CacheObjectEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, CacheObjectEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = hashFactory.hashFullDomain(bigIntegerValue);
                        encryptedValue = encryptedValue.modPow(serverPrivateExponent, modulus);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (Boolean.TRUE.equals(this.psiServerSession.getCacheEnabled())) {
                            CacheUtils.putCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, new CacheObjectEncrypted(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    encryptedSet.add(CustomTypeConverter.convertBigIntegerToString(encryptedValue));
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

        BigInteger serverPrivateExponent = CustomTypeConverter.convertStringToBigInteger(this.psiServerSession.getPsiServerKeyDescription().getPrivateExponent());
        BigInteger modulus = CustomTypeConverter.convertStringToBigInteger(this.psiServerSession.getPsiServerKeyDescription().getModulus());

        Map<Long, String> encryptedMap = new ConcurrentHashMap<>();
        List<Map<Long, String>> partitionList = PartitionHelper.partitionMap(inputMap, this.threads);
        ExecutorService executorService = Executors.newFixedThreadPool(partitionList.size());
        for (Map<Long, String> partition : partitionList) {
            executorService.submit(() -> {
                for (Map.Entry<Long, String> entry : partition.entrySet()) {
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(entry.getValue());
                    BigInteger encryptedValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if (Boolean.TRUE.equals(this.psiServerSession.getCacheEnabled())) {
                        Optional<CacheObjectEncrypted> encryptedCacheObjectOptional = CacheUtils.getCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, CacheObjectEncrypted.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = bigIntegerValue.modPow(serverPrivateExponent, modulus);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (Boolean.TRUE.equals(this.psiServerSession.getCacheEnabled())) {
                            CacheUtils.putCachedObject(this.keyId, CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, new CacheObjectEncrypted(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    encryptedMap.put(entry.getKey(), CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                }
            });
        }
        MultithreadingHelper.awaitTermination(executorService, this.threadTimeoutSeconds, log);

        this.statisticList.add(statistics.close());
        return encryptedMap;
    }

    @Override
    public PsiServerKeyDescription getServerKeyDescription() {
        log.debug("Called getServerKeyDescription");
        return this.psiServerSession.getPsiServerKeyDescription();
    }

    // Helper method used to validate the required fields of the psiServerKeyDescription for this algorithm
    private void validatePsiServerKeyDescription() {
        if (this.psiServerSession.getPsiServerKeyDescription() == null
                || this.psiServerSession.getPsiServerKeyDescription().getPrivateExponent() == null
                || this.psiServerSession.getPsiServerKeyDescription().getModulus() == null
        )
            throw new PsiServerException("The fields privateExponent and modulus of the PsiServerKeyDescription for DH should not be null");
    }
}
