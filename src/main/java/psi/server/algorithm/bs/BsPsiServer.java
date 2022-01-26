package psi.server.algorithm.bs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheUtils;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.EncryptedCacheObject;
import psi.model.PsiAlgorithmParameter;
import psi.cache.PsiCacheProvider;
import psi.exception.PsiServerInitException;
import psi.exception.PsiServerException;
import psi.server.*;
import psi.utils.CustomTypeConverter;
import psi.utils.HashFactory;
import psi.utils.PartitionHelper;
import psi.utils.PsiPhaseStatistics;
import psi.utils.AsymmetricKeyFactory;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

public class BsPsiServer extends PsiAbstractServer {

    private static final Logger log = LoggerFactory.getLogger(PsiAbstractServer.class);

    public BsPsiServer(PsiServerSession bsServerSession, PsiCacheProvider psiCacheProvider) {
        this.psiServerSession = bsServerSession;
        this.threads = PsiAbstractServer.DEFAULT_THREADS;
        this.statisticList = new LinkedList<>();

        if(psiCacheProvider != null){
            this.psiCacheProvider = psiCacheProvider;
            this.keyId = PsiCacheUtils.getKeyId(psiServerSession.getPsiServerKeyDescription(), psiCacheProvider);
        }
    }

    public static PsiServerSession initSession(PsiAlgorithmParameter psiAlgorithmParameter, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) {
        PsiServerSession psiServerSession = new PsiServerSession(psiAlgorithmParameter);

        // keys are created from scratch
        if (psiServerKeyDescription == null) {
            psiServerKeyDescription = AsymmetricKeyFactory.generateKey(psiAlgorithmParameter.getAlgorithm(), psiAlgorithmParameter.getKeySize());
        } // keys are loaded from serverKeyDescription
        else {
            if (psiServerKeyDescription.getModulus() == null || psiServerKeyDescription.getModulus().isEmpty()
                    || psiServerKeyDescription.getPrivateKey() == null || psiServerKeyDescription.getPrivateKey().isEmpty()
                    || psiServerKeyDescription.getPublicKey() == null || psiServerKeyDescription.getPublicKey().isEmpty())
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

        BigInteger serverPrivateKey = CustomTypeConverter.convertStringToBigInteger(psiServerSession.getPsiServerKeyDescription().getPrivateKey());
        BigInteger modulus = CustomTypeConverter.convertStringToBigInteger(psiServerSession.getPsiServerKeyDescription().getModulus());

        Set<String> encryptedSet = new HashSet<>();
        List<Set<String>> partitionList = PartitionHelper.partitionSet(inputSet, this.threads);
        List<FutureTask<Set<String>>> futureTaskList = new ArrayList<>(threads);
        for(Set<String> partition : partitionList) {
            FutureTask<Set<String>> futureTask = new FutureTask<>(() -> {
                HashFactory hashFactory = new HashFactory(modulus);
                Set<String> localDataset = new HashSet<>();

                for(String stringValue : partition){
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(stringValue);
                    BigInteger encryptedValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if(psiServerSession.getCacheEnabled()) {
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(this.keyId, PsiCacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, EncryptedCacheObject.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()){
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = hashFactory.hashFullDomain(bigIntegerValue);
                        encryptedValue = encryptedValue.modPow(serverPrivateKey, modulus);
                        encryptedValue = hashFactory.hash(encryptedValue);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (psiServerSession.getCacheEnabled()) {
                            PsiCacheUtils.putCachedObject(this.keyId, PsiCacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, new EncryptedCacheObject(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    localDataset.add(CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                }
                return localDataset;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<Set<String>> ft : futureTaskList) {
            try {
                encryptedSet.addAll(ft.get());
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }

        statisticList.add(statistics.close());
        return encryptedSet;
    }

    @Override
    public Map<Long, String> encryptDatasetMap(Map<Long, String> inputMap) {
        log.debug("Called encryptDatasetMap()");
        validatePsiServerKeyDescription();
        PsiPhaseStatistics statistics = PsiPhaseStatistics.startStatistic(PsiPhaseStatistics.PsiPhase.DOUBLE_ENCRYPTION);

        BigInteger serverPrivateKey = CustomTypeConverter.convertStringToBigInteger(psiServerSession.getPsiServerKeyDescription().getPrivateKey());
        BigInteger modulus = CustomTypeConverter.convertStringToBigInteger(psiServerSession.getPsiServerKeyDescription().getModulus());

        Map<Long, String> encryptedMap = new HashMap<>();
        List<Map<Long, String>> partitionList = PartitionHelper.partitionMap(inputMap, this.threads);
        List<FutureTask<Map<Long, String>>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, String> partition : partitionList) {
            FutureTask<Map<Long, String>> futureTask = new FutureTask<>(() -> {
                Map<Long, String> localDatasetMap = new HashMap<>();
                for(Map.Entry<Long, String> entry : partition.entrySet()){
                    BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(entry.getValue());
                    BigInteger encryptedValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if (psiServerSession.getCacheEnabled()) {
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(this.keyId, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, EncryptedCacheObject.class, this.psiCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()){
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            statistics.incrementCacheHit();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = bigIntegerValue.modPow(serverPrivateKey, modulus);
                        statistics.incrementCacheMiss();
                        // If the cache support is enabled, the result is stored in the cache
                        if (psiServerSession.getCacheEnabled()) {
                            PsiCacheUtils.putCachedObject(this.keyId, PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, new EncryptedCacheObject(encryptedValue), this.psiCacheProvider);
                        }
                    }
                    localDatasetMap.put(entry.getKey(), CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                }
                return localDatasetMap;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<Map<Long, String>> ft : futureTaskList) {
            try {
                encryptedMap.putAll(ft.get());
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }

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
                || psiServerSession.getPsiServerKeyDescription().getPrivateKey() == null
                || psiServerSession.getPsiServerKeyDescription().getPublicKey() == null
                || psiServerSession.getPsiServerKeyDescription().getModulus() == null
        ) throw new PsiServerException("The fields privateKey, publicKey and modulus of the PsiServerKeyDescription for BS should not be null");
    }
}
