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

public class HashFactory {

    private static final Logger log = LoggerFactory.getLogger(HashFactory.class);

    private MessageDigest digestHash;

    private int modulusByteLength;

    private String hashingAlgorithm = "SHA-256";

    public HashFactory(BigInteger modulus){
        this.modulusByteLength = (int) Math.ceil(modulus.bitLength() / 8.0) + 1;
        try {
            this.digestHash = MessageDigest.getInstance(hashingAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new CustomRuntimeException("The algorithm "+hashingAlgorithm+" is not supported as hashing function");
        }
    }

    public BigInteger hashFullDomain(BigInteger input) {
        return computeHashFullDomainInner(input, this.digestHash, this.modulusByteLength);
    }

    public BigInteger hash(BigInteger input) {
        return new BigInteger(this.digestHash.digest(input.toByteArray()));
    }

    private static BigInteger computeHashFullDomainInner(BigInteger input, MessageDigest digest, int modulusByteLength) {
        log.trace("Calling computeFullDomainHashInner with input = {}, modulusByteLength = {}", input, modulusByteLength);
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

    public String getHashingAlgorithm() {
        return hashingAlgorithm;
    }

    public static List<String> getSupportedHashAlgorithms() {
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
