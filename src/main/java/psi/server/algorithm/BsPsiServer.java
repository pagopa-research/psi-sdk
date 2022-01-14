package psi.server.algorithm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.EncryptionCacheUtils;
import psi.cache.enumeration.CacheOperationType;
import psi.cache.model.EncryptedCacheObject;
import psi.dto.SessionParameterDTO;
import psi.cache.EncryptionCacheProvider;
import psi.exception.PsiServerInitException;
import psi.exception.PsiServerException;
import psi.model.BsKeyDescription;
import psi.exception.MismatchedCacheKeyIdException;
import psi.server.PsiAbstractServer;
import psi.model.BsServerSession;
import psi.utils.CustomTypeConverter;
import psi.utils.HashFactory;
import psi.utils.PartitionHelper;

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

    public BsPsiServer(BsServerSession bsServerSession, EncryptionCacheProvider encryptionCacheProvider) {
        this.serverSession = bsServerSession;
        this.threads = PsiAbstractServer.DEFAULT_THREADS;

        if(encryptionCacheProvider != null){
            if(serverSession.getKeyId() == null)
                throw new PsiServerException("The field keyId of serverSession should always be different than null when cache is enabled");
            // TODO: add cache validation call
            this.encryptionCacheProvider = encryptionCacheProvider;
        }
    }

    public static BsServerSession initSession(SessionParameterDTO sessionParameterDTO, BsKeyDescription bsKeyDescription, EncryptionCacheProvider encryptionCacheProvider) {
        BsServerSession bsServerSession = new BsServerSession();
        bsServerSession.setAlgorithm(sessionParameterDTO.getAlgorithm());
        bsServerSession.setKeySize(sessionParameterDTO.getKeySize());

        // keys are created from scratch
        if (bsKeyDescription == null) {
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
            keyGenerator.initialize(sessionParameterDTO.getKeySize());
            KeyPair pair = keyGenerator.genKeyPair();

            try {
                RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
                bsServerSession.setModulus(CustomTypeConverter.convertBigIntegerToString(privateKeySpec.getModulus()));
                bsServerSession.setServerPrivateKey(CustomTypeConverter.convertBigIntegerToString(privateKeySpec.getPrivateExponent()));
                RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
                bsServerSession.setServerPublicKey(CustomTypeConverter.convertBigIntegerToString(publicKeySpec.getPublicExponent()));
            } catch (InvalidKeySpecException e) {
                log.error("Error: ", e);
                throw new PsiServerInitException("KeySpec is invalid. " +
                        "Verify whether both the input algorithm and key size are correct and compatible.");
            }

        // keys are loaded from bsKeyDescription
        } else {
            if (bsKeyDescription.getModulus() == null || bsKeyDescription.getModulus().isEmpty()
                    || bsKeyDescription.getPrivateKey() == null || bsKeyDescription.getPrivateKey().isEmpty()
                    || bsKeyDescription.getPublicKey() == null || bsKeyDescription.getPublicKey().isEmpty())
                throw new PsiServerInitException("The keys and/or modulus passed in the input keyDescription are either null or empty");

            // TODO: check whether keys are valid wrt each other
            bsServerSession.setServerPrivateKey(bsKeyDescription.getPrivateKey());
            bsServerSession.setServerPublicKey(bsKeyDescription.getPublicKey());
            bsServerSession.setModulus(bsKeyDescription.getModulus());
            if(bsKeyDescription.getKeyId() != null)
                bsServerSession.setKeyId(bsKeyDescription.getKeyId());
        }

        // if encryptionCacheProvider != null, enable and validate the cache
        if(encryptionCacheProvider == null)
            bsServerSession.setCacheEnabled(false);
        else{
            if(bsServerSession.getKeyId() == null)
                throw new PsiServerInitException("The keyId of the input bsKeyDescription is null despite being required to enable the cache");
            if(!EncryptionCacheUtils.verifyCacheKeyIdCorrectness(bsServerSession.getKeyId(), bsKeyDescription, encryptionCacheProvider))
                throw new MismatchedCacheKeyIdException();
            bsServerSession.setCacheEnabled(true);
        }

        return bsServerSession;
    }

    @Override
    public Set<String> encryptDataset(Set<String> inputSet) {
        log.debug("Called encryptDataset()");

        if (!(serverSession instanceof BsServerSession))
            throw new PsiServerException("The serverSession passed as input of encryptDataset() should be an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        BigInteger serverPrivateKey = CustomTypeConverter.convertStringToBigInteger(bsServerSession.getServerPrivateKey());
        BigInteger modulus = CustomTypeConverter.convertStringToBigInteger(bsServerSession.getModulus());

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
                    if(bsServerSession.getCacheEnabled()) {
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = EncryptionCacheUtils.getCachedObject(bsServerSession.getKeyId(), CacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, EncryptedCacheObject.class, this.encryptionCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent())
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = hashFactory.hashFullDomain(bigIntegerValue);
                        encryptedValue = encryptedValue.modPow(serverPrivateKey, modulus);
                        encryptedValue = hashFactory.hash(encryptedValue);
                        // If the cache support is enabled, the result is stored in the cache
                        if (bsServerSession.getCacheEnabled()) {
                            EncryptionCacheUtils.putCachedObject(bsServerSession.getKeyId(), CacheOperationType.PRIVATE_KEY_HASH_ENCRYPTION, bigIntegerValue, new EncryptedCacheObject(encryptedValue), this.encryptionCacheProvider);
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
        return encryptedSet;
    }

    @Override
    public Map<Long, String> encryptDatasetMap(Map<Long, String> inputMap) {
        log.debug("Called encryptDatasetMap()");

        if (!(serverSession instanceof BsServerSession))
            throw new PsiServerException("The serverSession passed as input of encryptDataset() should be an instance of the subclass BsServerSession");
        BsServerSession bsServerSession = (BsServerSession) serverSession;
        BigInteger serverPrivateKey = CustomTypeConverter.convertStringToBigInteger(bsServerSession.getServerPrivateKey());
        BigInteger modulus = CustomTypeConverter.convertStringToBigInteger(bsServerSession.getModulus());

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
                    if (bsServerSession.getCacheEnabled()) {
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = EncryptionCacheUtils.getCachedObject(bsServerSession.getKeyId(), CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, EncryptedCacheObject.class, this.encryptionCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent())
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        encryptedValue = bigIntegerValue.modPow(serverPrivateKey, modulus);
                        // If the cache support is enabled, the result is stored in the cache
                        if (bsServerSession.getCacheEnabled()) {
                            EncryptionCacheUtils.putCachedObject(bsServerSession.getKeyId(), CacheOperationType.PRIVATE_KEY_ENCRYPTION, bigIntegerValue, new EncryptedCacheObject(encryptedValue), this.encryptionCacheProvider);
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
        return encryptedMap;
    }
}
