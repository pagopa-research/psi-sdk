package psi.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashFactory {

    private static final Logger log = LoggerFactory.getLogger("FullHashDomain");

    private MessageDigest digestHashFullDomain;
    private MessageDigest digestHash;

    private int modulusByteLength;

    private String hashingAlgorithm = "SHA-256"; //TODO: change this value depending on the modulus length
    private String fullDomainHashingAlgorithm = "SHA-256"; //TODO: change this value depending on the modulus length

    public HashFactory(BigInteger modulus) throws NoSuchAlgorithmException {
        this.modulusByteLength = (int) Math.ceil(modulus.bitLength() / 8.0) + 1;
        this.digestHashFullDomain = MessageDigest.getInstance(fullDomainHashingAlgorithm);
        if(hashingAlgorithm.equalsIgnoreCase(fullDomainHashingAlgorithm))
            this.digestHash = this.digestHashFullDomain;
        else
            this.digestHash = MessageDigest.getInstance(hashingAlgorithm);
    }

    public BigInteger hashFullDomain(BigInteger input) {
        return computeHashFullDomainInner(input, this.digestHashFullDomain, this.modulusByteLength);
    }

    public BigInteger hash(BigInteger input) {
        return new BigInteger(this.digestHash.digest(input.toByteArray()));
    }

    public static BigInteger hashFullDomainStatic(BigInteger input, String hashingAlgorithm, BigInteger modulus) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(hashingAlgorithm);
        int modulusByteLength = modulus.bitLength();
        return computeHashFullDomainInner(input, digest, modulusByteLength);
    }

    public static BigInteger computeHashFullDomainInner(BigInteger input, MessageDigest digest, int modulusByteLength) {
        log.debug("Calling computeFullDomainHashInner with input = {}, modulusByteLength = {}", input, modulusByteLength);
        byte[] result = new byte[modulusByteLength];
        result[0] = (byte) 0xff;
        // Create a temp structure used to store the value to be hashed: (input | i) with i in (1,n)
        int incPosition = input.toByteArray().length;
        byte[] inputArray = new byte[incPosition + 1];
        System.arraycopy(input.toByteArray(), 0, inputArray, 0, incPosition);
        // The last byte is used to generate different inputs during the iterations
        inputArray[incPosition] = 0;
        int pos = 0;

        while (pos < modulusByteLength){
            byte[] hashedValue = digest.digest(inputArray);
            System.arraycopy(hashedValue, 0, result, pos,
                    pos+hashedValue.length < modulusByteLength ? hashedValue.length : modulusByteLength - pos);

            pos += hashedValue.length;
            inputArray[incPosition]++;
        }

        return new BigInteger(result);
    }

    public void setHashingAlgorithm(String hashingAlgorithm) throws NoSuchAlgorithmException {
        this.hashingAlgorithm = hashingAlgorithm;
        this.digestHash = MessageDigest.getInstance(hashingAlgorithm);

    }

    public void setFullDomainHashingAlgorithm(String fullDomainHashingAlgorithm) throws NoSuchAlgorithmException {
        this.fullDomainHashingAlgorithm = fullDomainHashingAlgorithm;
        this.digestHashFullDomain = MessageDigest.getInstance(fullDomainHashingAlgorithm);
    }

    public String getFullDomainHashingAlgorithm() {
        return fullDomainHashingAlgorithm;
    }

    public String getHashingAlgorithm() {
        return hashingAlgorithm;
    }
}
