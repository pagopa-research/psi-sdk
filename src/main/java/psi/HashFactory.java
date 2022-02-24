package psi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import psi.exception.CustomRuntimeException;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;

/**
 * Provides hashing functionalities. The default digest algorithm is SHA-256, but can be modified at runtime.
 */
class HashFactory {

    private static final Logger log = LoggerFactory.getLogger(HashFactory.class);

    private MessageDigest digestHash;

    private final int modulusByteLength;

    private String hashingAlgorithm = "SHA-256";

    HashFactory(BigInteger modulus){
        this.modulusByteLength = (int) Math.ceil(modulus.bitLength() / 8.0) + 1;
        try {
            this.digestHash = MessageDigest.getInstance(this.hashingAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CustomRuntimeException("The algorithm "+ this.hashingAlgorithm +" is not supported as hashing function");
        }
    }

    /**
     * Computes a digest of the input value using a full hash domain function, namely a hash function that maps to an
     * output value whose size equals the one expressed by the modulusByteLength variable.
     * @param input value to be hashed
     * @return a BigInteger representation of the result of the full hash domain function
     */
    BigInteger hashFullDomain(BigInteger input) {
        log.trace("Calling hashFullDomain with input = {}", input);
        byte[] result = new byte[this.modulusByteLength];
        result[0] = (byte) 0xff;
        // Creates a temp structure used to store the value to be hashed: (input | i) with i in (1,n)
        int incPosition = input.toByteArray().length;
        byte[] inputArray = new byte[incPosition + 1];
        System.arraycopy(input.toByteArray(), 0, inputArray, 0, incPosition);
        // The last byte is used to generate different inputs, by incrementing it at each iteration
        inputArray[incPosition] = 0;
        int pos = 0;

        while (pos < this.modulusByteLength){
            byte[] hashedValue = this.digestHash.digest(inputArray);
            System.arraycopy(hashedValue, 0, result, pos,
                    pos+hashedValue.length < this.modulusByteLength ? hashedValue.length : this.modulusByteLength - pos);

            pos += hashedValue.length;
            inputArray[incPosition]++;
        }

        return new BigInteger(result);
    }

    /**
     * Computes a digest of the input value.
     * @param input value to be hashed
     * @return  a BigInteger representation of the result of the hash function
     */
    BigInteger hash(BigInteger input) {
        return new BigInteger(this.digestHash.digest(input.toByteArray()));
    }

    /**
     * Sets the hashing algorithm used to perform internal operations.
     * @param hashingAlgorithm String representation of the hashing algorithm to be used
     * @throws NoSuchAlgorithmException if no Provider supports a MessageDigest implementation for the specified algorithm.
     */
    void setHashingAlgorithm(String hashingAlgorithm) throws NoSuchAlgorithmException {
        this.hashingAlgorithm = hashingAlgorithm;
        this.digestHash = MessageDigest.getInstance(hashingAlgorithm);

    }

    /**
     * Retrieve the currently used hashing algorithm.
     * @return the currently used hashing algorithm.
     */
    String getHashingAlgorithm() {
        return this.hashingAlgorithm;
    }

    /**
     * Retrieve the list of hashing algorithms offered by the current security provider.
     * @return the list of supported hashing algorithm
     */
    static List<String> getSupportedHashAlgorithms() {
        List<String> algorithmList = new LinkedList<>();
        String type = (MessageDigest.class).getSimpleName();
        for (Provider prov : Security.getProviders()) {
            for (Service service : prov.getServices()) {
                if (service.getType().equalsIgnoreCase(type)) {
                    algorithmList.add(service.getAlgorithm());
                }
            }
        }
        return algorithmList;
    }
}
