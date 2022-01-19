package psi.server.algorithm.bs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheUtils;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.EncryptedCacheObject;
import psi.client.PsiClientKeyDescriptionFactory;
import psi.dto.PsiAlgorithmParameterDTO;
import psi.cache.PsiCacheProvider;
import psi.exception.PsiServerInitException;
import psi.exception.PsiServerException;
import psi.exception.MismatchedCacheKeyIdException;
import psi.server.*;
import psi.utils.CustomTypeConverter;
import psi.utils.HashFactory;
import psi.utils.PartitionHelper;
import psi.utils.StatisticsFactory;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
            if(psiServerSession.getPsiServerKeyDescription().getKeyId() == null)
                throw new PsiServerException("The field keyId of serverSession should always be different than null when cache is enabled");
            // TODO: add cache validation call
            this.psiCacheProvider = psiCacheProvider;
        }
    }

    public static PsiServerSession initSession(PsiAlgorithmParameterDTO psiAlgorithmParameterDTO, PsiServerKeyDescription psiServerKeyDescription, PsiCacheProvider psiCacheProvider) {
        PsiServerSession psiServerSession = new PsiServerSession();
        psiServerSession.setAlgorithm(psiAlgorithmParameterDTO.getAlgorithm().toString());
        psiServerSession.setKeySize(psiAlgorithmParameterDTO.getKeySize());

        // keys are created from scratch
        if (psiServerKeyDescription == null) {
            KeyPairGenerator keyGenerator;
            KeyFactory keyFactory;
            try {
                String keyType = "RSA";
                keyGenerator = KeyPairGenerator.getInstance(keyType);
                keyFactory = KeyFactory.getInstance(keyType);
            } catch (NoSuchAlgorithmException e) {
                log.error("Error ", e);
                throw new PsiServerInitException("RSA key generator not available");
            }
            keyGenerator.initialize(psiAlgorithmParameterDTO.getKeySize());
            KeyPair pair = keyGenerator.genKeyPair();

            try {
                RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
                RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
                psiServerSession.setPsiServerKeyDescription(PsiServerKeyDescriptionFactory.createBsServerKeyDescription(
                        CustomTypeConverter.convertBigIntegerToString(privateKeySpec.getPrivateExponent()),
                        CustomTypeConverter.convertBigIntegerToString(publicKeySpec.getPublicExponent()),
                        CustomTypeConverter.convertBigIntegerToString(privateKeySpec.getModulus())));
            } catch (InvalidKeySpecException e) {
                log.error("Error: ", e);
                throw new PsiServerInitException("KeySpec is invalid. " +
                        "Verify whether both the input algorithm and key size are correct and compatible.");
            }

        // keys are loaded from bsServerKeyDescription
        } else {
            if (psiServerKeyDescription.getModulus() == null || psiServerKeyDescription.getModulus().isEmpty()
                    || psiServerKeyDescription.getPrivateKey() == null || psiServerKeyDescription.getPrivateKey().isEmpty()
                    || psiServerKeyDescription.getPublicKey() == null || psiServerKeyDescription.getPublicKey().isEmpty())
                throw new PsiServerInitException("The keys and/or modulus passed in the input psiServerKeyDescription are either null or empty");

            // TODO: check whether keys are valid wrt each other
            psiServerSession.setPsiServerKeyDescription(psiServerKeyDescription);
        }

        // if psiCacheProvider != null, enable and validate the cache
        if(psiCacheProvider == null)
            psiServerSession.setCacheEnabled(false);
        else{
            if(psiServerSession.getPsiServerKeyDescription().getKeyId() == null)
                throw new PsiServerInitException("The keyId of the input psiServerKeyDescription is null despite being required to enable the cache");
            if(!PsiCacheUtils.verifyCacheKeyIdCorrectness(psiServerSession.getPsiServerKeyDescription().getKeyId(), psiServerKeyDescription, psiCacheProvider))
                throw new MismatchedCacheKeyIdException();
            psiServerSession.setCacheEnabled(true);
        }

        return psiServerSession;
    }

    @Override
    public Set<String> encryptDataset(Set<String> inputSet) {
        log.debug("Called encryptDataset()");

        validatePsiServerKeyDescription();
        StatisticsFactory statistics = new StatisticsFactory(StatisticsFactory.PsiPhase.ENCRYPTION);

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
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(psiServerSession.getPsiServerKeyDescription().getKeyId(), PsiCacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, EncryptedCacheObject.class, this.psiCacheProvider);
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
                            PsiCacheUtils.putCachedObject(psiServerSession.getPsiServerKeyDescription().getKeyId(), PsiCacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, new EncryptedCacheObject(encryptedValue), this.psiCacheProvider);
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
        StatisticsFactory statistics = new StatisticsFactory(StatisticsFactory.PsiPhase.DOUBLE_ENCRYPTION);

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
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(psiServerSession.getPsiServerKeyDescription().getKeyId(), PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, EncryptedCacheObject.class, this.psiCacheProvider);
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
                            PsiCacheUtils.putCachedObject(psiServerSession.getPsiServerKeyDescription().getKeyId(), PsiCacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, new EncryptedCacheObject(encryptedValue), this.psiCacheProvider);
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
