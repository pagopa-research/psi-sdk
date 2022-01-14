package psi.client.algorithm.bs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.cache.PsiCacheProvider;
import psi.cache.PsiCacheUtils;
import psi.cache.enumeration.PsiCacheOperationType;
import psi.cache.model.EncryptedCacheObject;
import psi.cache.model.RandomEncryptedCacheObject;
import psi.client.PsiAbstractClient;
import psi.client.PsiClient;
import psi.client.algorithm.bs.model.BsPsiClientKeyDescription;
import psi.client.model.PsiClientKeyDescription;
import psi.dto.PsiSessionDTO;
import psi.exception.MismatchedCacheKeyIdException;
import psi.exception.PsiClientException;
import psi.utils.CustomTypeConverter;
import psi.utils.HashFactory;
import psi.utils.PartitionHelper;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

public class BsPsiClient extends PsiAbstractClient {

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private static final int RANDOM_BITS = 2048;

    private BigInteger seed;
    private final Map<Long, BigInteger> clientClearDatasetMap;
    private final Map<Long, BigInteger> clientRandomDatasetMap;
    private final Map<Long, BigInteger> clientEncryptedDatasetMap;
    private final Map<Long, BigInteger> clientDoubleEncryptedDatasetMap;
    private final Map<Long, BigInteger> clientReversedDatasetMap;

    private BigInteger modulus;
    private BigInteger serverPublicKey;

    public BsPsiClient(PsiSessionDTO psiSessionDTO, BsPsiClientKeyDescription bsPsiClientKeyDescription, PsiCacheProvider psiCacheProvider){
        this.sessionId = psiSessionDTO.getSessionId();
        this.serverEncryptedDataset = new HashSet<>();
        this.clientClearDatasetMap = new HashMap<>();
        this.clientRandomDatasetMap = new HashMap<>();
        this.clientEncryptedDatasetMap = new HashMap<>();
        this.clientDoubleEncryptedDatasetMap = new HashMap<>();
        this.clientReversedDatasetMap = new HashMap<>();
        this.threads = DEFAULT_THREADS;

        // By default, a new seed for the blind signature is created. It can be overwritten with the setter method
        this.seed = new BigInteger(RANDOM_BITS, new SecureRandom());

        // keys are set from the psiSessionDTO
        if(bsPsiClientKeyDescription == null) {
            this.modulus = CustomTypeConverter.convertStringToBigInteger(psiSessionDTO.getModulus());
            this.serverPublicKey = CustomTypeConverter.convertStringToBigInteger(psiSessionDTO.getServerPublicKey());
        }
        // keys are loaded from bsClientKeyDescription, but should still match those of psiSessionDTO
        else{
            if(bsPsiClientKeyDescription.getModulus() == null || bsPsiClientKeyDescription.getServerPublicKey() == null)
                throw new PsiClientException("The fields modulus and serverPrivateKey in the input bsClientKeyDescription cannot be null");
            if(!psiSessionDTO.getModulus().equals(bsPsiClientKeyDescription.getModulus()) || !psiSessionDTO.getServerPublicKey().equals(bsPsiClientKeyDescription.getServerPublicKey()))
                throw new PsiClientException("The fields modulus and/or serverPrivateKey in the bsClientKeyDescription does not match those in the psiSessionDTO");
            if(bsPsiClientKeyDescription.getKeyId() != null)
                this.keyId = bsPsiClientKeyDescription.getKeyId();
            this.modulus = CustomTypeConverter.convertStringToBigInteger(bsPsiClientKeyDescription.getModulus());
            this.serverPublicKey = CustomTypeConverter.convertStringToBigInteger(bsPsiClientKeyDescription.getServerPublicKey());
        }

        // TODO: check whether keys are valid wrt each other. Needed both when using the clientKeyDescription and when only using the psiSessionDTO

        // If psiCacheProvider != null, setup and validate the cache
        if(psiCacheProvider == null)
            this.cacheEnabled = false;
        else{
            if(this.keyId == null)
                throw new PsiClientException("The keyId of the input bsClientKeyDescription is null despite being required to enable the cache");
            if(!PsiCacheUtils.verifyCacheKeyIdCorrectness(this.keyId, bsPsiClientKeyDescription, psiCacheProvider))
                    throw new MismatchedCacheKeyIdException();
            this.cacheEnabled = true;
        }
    }

    public BigInteger getSeed() {
        return seed;
    }

    public void setSeed(BigInteger seed) {
        this.seed = seed;
    }

    @Override
    public Map<Long, String> loadAndEncryptClientDataset(Map<Long, String> clearClientDataset) {
        log.debug("Called loadAndEncryptClientDataset");
        List<Map<Long, String>> clientDatasetPartitions = PartitionHelper.partitionMap(clearClientDataset, this.threads);
        Map<Long, String> clientEncryptedDatasetMapConvertedToString = new HashMap<>();

        List<FutureTask<BsMapQuartet>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, String> partition : clientDatasetPartitions) {
            FutureTask<BsMapQuartet> futureTask = new FutureTask<>(() -> {
                Map<Long, BigInteger> localClientClearDatasetMap = new HashMap<>();
                Map<Long, BigInteger> localClientRandomDatasetMap = new HashMap<>();
                Map<Long, BigInteger> localClientEncryptedDatasetMap = new HashMap<>();
                Map<Long, String> localClientEncryptedDatasetMapConvertedToString = new HashMap<>();
                HashFactory hashFactory = new HashFactory(modulus);

                for(Map.Entry<Long, String> entry : partition.entrySet()){
                     BigInteger bigIntegerValue = CustomTypeConverter.convertStringToBigInteger(entry.getValue());
                    BigInteger encryptedValue = null;
                    BigInteger randomValue = null;
                    // If the cache support is enabled, the result is searched in the cache
                    if(this.cacheEnabled) {
                        Optional<RandomEncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(keyId, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, RandomEncryptedCacheObject.class, this.encryptionCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            encryptedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                            randomValue = encryptedCacheObjectOptional.get().getRandomValue();
                        }
                    }
                    // If the cache support is not enabled or if the corresponding value is not available, it has to be computed
                    if (encryptedValue == null) {
                        randomValue = (seed.xor(bigIntegerValue)).mod(modulus); // new BigInteger(modulus.bitCount(), secureRandom).mod(modulus)
                        encryptedValue = randomValue.modPow(serverPublicKey, modulus).multiply(hashFactory.hashFullDomain(bigIntegerValue)).mod(modulus);
                        if(this.cacheEnabled) {
                            PsiCacheUtils.putCachedObject(keyId, PsiCacheOperationType.BLIND_SIGNATURE_ENCRYPTION, bigIntegerValue, new RandomEncryptedCacheObject(randomValue, encryptedValue),this.encryptionCacheProvider);
                        }
                    }
                     localClientClearDatasetMap.put(entry.getKey(), bigIntegerValue);
                     localClientRandomDatasetMap.put(entry.getKey(), randomValue);
                     localClientEncryptedDatasetMap.put(entry.getKey(), encryptedValue);
                     localClientEncryptedDatasetMapConvertedToString.put(entry.getKey(), CustomTypeConverter.convertBigIntegerToString(encryptedValue));
                 }

                 BsMapQuartet bsMapQuartet = new BsMapQuartet();
                 bsMapQuartet.clearMap = localClientClearDatasetMap;
                 bsMapQuartet.randomMap = localClientRandomDatasetMap;
                 bsMapQuartet.encryptedMap = localClientEncryptedDatasetMap;
                 bsMapQuartet.encryptedMapConvertedToString = localClientEncryptedDatasetMapConvertedToString;
                 return bsMapQuartet;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<BsMapQuartet> ft : futureTaskList) {
            try {
                clientClearDatasetMap.putAll(ft.get().clearMap);
                clientRandomDatasetMap.putAll(ft.get().randomMap);
                clientEncryptedDatasetMap.putAll(ft.get().encryptedMap);
                clientEncryptedDatasetMapConvertedToString.putAll(ft.get().encryptedMapConvertedToString);
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }
        return clientEncryptedDatasetMapConvertedToString;
    }

    @Override
    public void loadDoubleEncryptedClientDataset(Map<Long, String> doubleEncryptedClientDatasetMap){
        log.debug("Called loadDoubleEncryptedClientDataset");
        for(Map.Entry<Long, String> entry : doubleEncryptedClientDatasetMap.entrySet()) {
            this.clientDoubleEncryptedDatasetMap.put(entry.getKey(), CustomTypeConverter.convertStringToBigInteger(entry.getValue()));
        }
    }

    @Override
    public void loadServerDataset(Set<String> serverEncryptedDataset) {
        log.debug("Called loadServerDataset");
        for(String value : serverEncryptedDataset) {
            this.serverEncryptedDataset.add(CustomTypeConverter.convertStringToBigInteger(value));
        }
    }

    // Loads the clientReversedDatasetMap which contains a decryption of the clientDoubleEncryptedDatasetMap entries
    private void computeReversedMap(){
        log.debug("Called computeReversedMap");
        List<Map<Long, BigInteger>> doubleEncryptedMapPartition = PartitionHelper.partitionMap(clientDoubleEncryptedDatasetMap, threads);
        List<FutureTask<Map<Long, BigInteger>>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, BigInteger> partition : doubleEncryptedMapPartition){
            FutureTask<Map<Long, BigInteger>> futureTask = new FutureTask<>(() -> {
                HashFactory hashFactory = new HashFactory(modulus);
                Map<Long, BigInteger> localClientReversedDatasetMap = new HashMap<>();
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()) {
                    BigInteger reversedValue = null;
                    if (this.cacheEnabled) {
                        //TODO: controllare se sia corretto o se è meglio usare una chiave composta con i parametri in input alla funzione sottostante
                        Optional<EncryptedCacheObject> encryptedCacheObjectOptional = PsiCacheUtils.getCachedObject(keyId, PsiCacheOperationType.REVERSE_VALUE, clientClearDatasetMap.get(entry.getKey()), EncryptedCacheObject.class, this.encryptionCacheProvider);
                        if (encryptedCacheObjectOptional.isPresent()) {
                            reversedValue = encryptedCacheObjectOptional.get().getEncryptedValue();
                        }
                    }
                    if (reversedValue == null){
                        reversedValue = hashFactory.hash(entry.getValue().multiply(clientRandomDatasetMap.get(entry.getKey()).modInverse(modulus)).mod(modulus));
                        if (this.cacheEnabled) {
                            PsiCacheUtils.putCachedObject(keyId, PsiCacheOperationType.REVERSE_VALUE, clientClearDatasetMap.get(entry.getKey()), new EncryptedCacheObject(reversedValue), this.encryptionCacheProvider); //TODO, come sopra
                        }
                    }
                    localClientReversedDatasetMap.put(entry.getKey(), reversedValue);
                }
                return localClientReversedDatasetMap;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<Map<Long, BigInteger>> ft : futureTaskList) {
            try {
                clientReversedDatasetMap.putAll(ft.get());
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }
    }

    @Override
    public Set<String> computePsi(){
        log.debug("Called loadServerDataset");
        computeReversedMap();
        Set<String> psi = new HashSet<>();
        List<Map<Long, BigInteger>> reversedMapPartition = PartitionHelper.partitionMap(clientReversedDatasetMap, threads);
        List<FutureTask<Set<String>>> futureTaskList = new ArrayList<>(threads);
        for(Map<Long, BigInteger> partition : reversedMapPartition){
            FutureTask<Set<String>> futureTask = new FutureTask<>(() -> {
                Set<String> partitionPsiSet = new HashSet<>();
                for(Map.Entry<Long, BigInteger> entry : partition.entrySet()){
                    if(serverEncryptedDataset.contains(entry.getValue()))
                        partitionPsiSet.add(CustomTypeConverter.convertBigIntegerToString(clientClearDatasetMap.get(entry.getKey())));
                }
                return partitionPsiSet;
            });
            (new Thread(futureTask)).start();
            futureTaskList.add(futureTask);
        }

        // Collect results from the different threads
        for (FutureTask<Set<String>> ft : futureTaskList) {
            try {
                psi.addAll(ft.get());
            } catch (InterruptedException | ExecutionException e) {
                log.error("Error while collecting the results of threads: ", e);
            }
        }
        return psi;
    }

    @Override
    public PsiClientKeyDescription getClientKeyDescription() {
        BsPsiClientKeyDescription bsPsiClientKeyDescription = new BsPsiClientKeyDescription();
        bsPsiClientKeyDescription.setKeyId(this.keyId);
        bsPsiClientKeyDescription.setModulus(CustomTypeConverter.convertBigIntegerToString(this.modulus));
        bsPsiClientKeyDescription.setServerPublicKey(CustomTypeConverter.convertBigIntegerToString(this.serverPublicKey));
        return bsPsiClientKeyDescription;
    }

    // Helper class that bundles a quartet of maps. Three <Long, BigInteger> and one <Long, String>
     static class BsMapQuartet{
        public Map<Long, BigInteger> clearMap;
        public Map<Long, BigInteger> randomMap;
        public Map<Long, BigInteger> encryptedMap;
        public Map<Long, String> encryptedMapConvertedToString;
    }
}
