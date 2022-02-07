package psi.server.algorithm.ecbs;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheProvider;
import psi.cache.PsiCacheUtils;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.EncryptedEcCacheObject;
import psi.exception.PsiServerException;
import psi.exception.PsiServerInitException;
import psi.exception.UnsupportedKeySizeException;
import psi.exception.UnsupportedKeySizeRuntimeException;
import psi.model.EllipticCurve;
import psi.model.PsiAlgorithm;
import psi.model.PsiAlgorithmParameter;
import psi.model.PsiPhaseStatistics;
import psi.server.PsiAbstractServer;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerSession;
import psi.utils.AsymmetricKeyFactory;
import psi.utils.CustomTypeConverter;
import psi.utils.MultithreadingHelper;
import psi.utils.PartitionHelper;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class EcBsPsiServer extends PsiAbstractServer {

    private static final Logger log = LoggerFactory.getLogger(EcBsPsiServer.class);

    public EcBsPsiServer(PsiServerSession psiServerSession, PsiCacheProvider psiCacheProvider) {
        if (!PsiAlgorithm.ECBS.getSupportedKeySize().contains(psiServerSession.getPsiAlgorithmParameter().getKeySize()))
            throw new UnsupportedKeySizeRuntimeException(PsiAlgorithm.ECBS, psiServerSession.getPsiAlgorithmParameter().getKeySize());

        this.psiServerSession = psiServerSession;
        this.statisticList = new LinkedList<>();

        if (psiCacheProvider != null) {
            this.psiCacheProvider = psiCacheProvider;
            this.keyId = PsiCacheUtils.getKeyId(this.psiServerSession.getPsiServerKeyDescription(), psiCacheProvider);
        }
    }

    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) throws UnsupportedKeySizeException {
        log.debug("Called initSession()");

        if (!PsiAlgorithm.ECBS.getSupportedKeySize().contains(psiAlgorithmParameter.getKeySize()))
            throw new UnsupportedKeySizeException(PsiAlgorithm.ECBS, psiAlgorithmParameter.getKeySize());
        PsiServerSession psiServerSession = new PsiServerSession(psiAlgorithmParameter);

        // keys are created from scratch
        if (psiServerKeyDescription == null) {
            psiServerKeyDescription = AsymmetricKeyFactory.generateServerKey(psiAlgorithmParameter.getAlgorithm(), psiAlgorithmParameter.getKeySize());
        } // keys are loaded from serverKeyDescription
        else {
            if (psiServerKeyDescription.getEcSpecName() == null || psiServerKeyDescription.getEcPrivateKey() == null || psiServerKeyDescription.getEcPublicKey() == null)
                throw new PsiServerInitException("The keys and/or modulus passed in the input psiServerKeyDescription are either null or empty");
            // TODO: check whether keys are valid wrt each other
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

        BigInteger serverPrivateKey = CustomTypeConverter.convertStringToBigInteger(
                psiServerSession.getPsiServerKeyDescription().getEcPrivateKey());
        EllipticCurve ellipticCurve = new EllipticCurve(CustomTypeConverter.convertStringToECParameterSpec(
                psiServerSession.getPsiServerKeyDescription().getEcSpecName()));
        BigInteger privateKeyInverse = serverPrivateKey.modInverse(ellipticCurve.getN());
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
                    if(psiServerSession.getCacheEnabled()) {
                        Optional<EncryptedEcCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(this.keyId, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, EncryptedEcCacheObject.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()){
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = EllipticCurve.multiply(ellipticCurve.mapMessage(bigIntegerValue), privateKeyInverse);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (psiServerSession.getCacheEnabled()) {
                            PsiCacheUtils.putCachedObject(this.keyId, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, new EncryptedEcCacheObject(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    encryptedSet.add(CustomTypeConverter.convertECPointToString(encryptedValue));
                }
            });
        }
        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

        statisticList.add(statistics.close());
        return encryptedSet;
    }

    @Override
    public Map<Long, String> encryptDatasetMap(Map<Long, String> inputMap) {
        log.debug("Called encryptDatasetMap()");
        validatePsiServerKeyDescription();
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.DOUBLE_ENCRYPTION);



        BigInteger serverPrivateKey = CustomTypeConverter.convertStringToBigInteger(
                psiServerSession.getPsiServerKeyDescription().getEcPrivateKey());
        EllipticCurve ellipticCurve = new EllipticCurve(CustomTypeConverter.convertStringToECParameterSpec(
                psiServerSession.getPsiServerKeyDescription().getEcSpecName()));
        BigInteger privateKeyInverse = serverPrivateKey.modInverse(ellipticCurve.getN());
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
                    if (psiServerSession.getCacheEnabled()) {
                        Optional<EncryptedEcCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(this.keyId, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, keyValue, EncryptedEcCacheObject.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()){
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue(ecCurve);
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = EllipticCurve.multiply(ecPointValue, privateKeyInverse);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (psiServerSession.getCacheEnabled()) {
                            PsiCacheUtils.putCachedObject(this.keyId, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, keyValue, new EncryptedEcCacheObject(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    encryptedMap.put(entry.getKey(), CustomTypeConverter.convertECPointToString(encryptedValue));
                }
            });
        }
        MultithreadingHelper.awaitTermination(executorService, threadTimeoutSeconds, log);

        statisticList.add(statistics.close());
        return encryptedMap;
    }

    @Override
    public PsiServerKeyDescription getServerKeyDescription() {
        return psiServerSession.getPsiServerKeyDescription();
    }

    // Helper method used to validate the required fields of the psiServerKeyDescription for this algorithm
    private void validatePsiServerKeyDescription(){
        if(psiServerSession.getPsiServerKeyDescription() == null
                || psiServerSession.getPsiServerKeyDescription().getEcPrivateKey() == null
                || psiServerSession.getPsiServerKeyDescription().getEcPublicKey() == null
                || psiServerSession.getPsiServerKeyDescription().getEcSpecName() == null
        ) throw new PsiServerException("The fields ecPrivateKey, ecPublicKey and ecSpec of the PsiServerKeyDescription for BS should not be null");
    }
}
