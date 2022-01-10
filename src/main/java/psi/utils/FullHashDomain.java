package psi.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FullHashDomain {

    private static final Logger log = LoggerFactory.getLogger("FullHashDomain");

    private MessageDigest digest;

    private int modulusByteLength;

    public FullHashDomain(String hashingAlgorithm, BigInteger modulus) throws NoSuchAlgorithmException {
        this.digest = MessageDigest.getInstance(hashingAlgorithm);
        // An additional byte is required to ensure that the final value is as long as the modulus
        // Indeed, the conversion from an array of bytes and a big integer creates an offset of 1
        this.modulusByteLength = (int) Math.ceil(modulus.bitLength() / 8.0) + 1;
    }

    public BigInteger process(BigInteger input) {
        return computeFullDomainHashInner(input, this.digest, this.modulusByteLength);
    }

    public static BigInteger processStatic(BigInteger input, String hashingAlgorithm, BigInteger modulus) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(hashingAlgorithm);
        int modulusByteLength = modulus.bitLength();
        return computeFullDomainHashInner(input, digest, modulusByteLength);
    }

    private static BigInteger computeFullDomainHashInner(BigInteger input, MessageDigest digest, int modulusByteLength) {
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

}
