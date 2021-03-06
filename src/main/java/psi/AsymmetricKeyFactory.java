package psi;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.exception.KeyGenerationException;
import psi.model.PsiAlgorithm;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Provides facilities to retrieve the client/server keys, namely the values used during the mathematical
 * encryption operations, whenever they are not explicitly provided by the user.
 */

class AsymmetricKeyFactory {

    private AsymmetricKeyFactory() {}

    /**
     * Generates a server key for the input PSI algorithm and keySize.
     *
     * @param algorithm a PsiAlgorithm enum. Should be either EC, BS, ECDH or ECBS, else throws an exception
     * @param keySize   size of the key
     * @return PsiServerKeyDescription containing the generated key
     */
    static PsiServerKeyDescription generateServerKeyDescription(PsiAlgorithm algorithm, int keySize) {
        if (algorithm.equals(PsiAlgorithm.BS) || algorithm.equals(PsiAlgorithm.DH)) {
            AsymmetricKey asymmetricKey = generateKey(algorithm, keySize);
            if (algorithm.equals(PsiAlgorithm.BS))
                return PsiServerKeyDescriptionFactory
                        .createBsServerKeyDescription(
                                CustomTypeConverter.convertBigIntegerToString(asymmetricKey.privateExponent),
                                CustomTypeConverter.convertBigIntegerToString(asymmetricKey.publicExponent),
                                CustomTypeConverter.convertBigIntegerToString(asymmetricKey.modulus));
            else
                return PsiServerKeyDescriptionFactory
                        .createDhServerKeyDescription(
                                CustomTypeConverter.convertBigIntegerToString(asymmetricKey.privateExponent),
                                CustomTypeConverter.convertBigIntegerToString(asymmetricKey.modulus),
                                CustomTypeConverter.convertBigIntegerToString(asymmetricKey.generator));
        }

        if (algorithm.equals(PsiAlgorithm.ECBS) || algorithm.equals(PsiAlgorithm.ECDH)) {
            AsymmetricEcKey asymmetricEcKey = generateEcKey(algorithm, keySize);
            if(algorithm.equals(PsiAlgorithm.ECBS))
                return PsiServerKeyDescriptionFactory
                        .createEcBsServerKeyDescription(
                                CustomTypeConverter.convertBigIntegerToString(asymmetricEcKey.privateD),
                                CustomTypeConverter.convertECPointToString(asymmetricEcKey.publicQ));
            else
                return PsiServerKeyDescriptionFactory
                        .createEcDhServerKeyDescription(
                                CustomTypeConverter.convertBigIntegerToString(asymmetricEcKey.privateD));
        }

        throw new KeyGenerationException("Algorithm not supported");
    }

    /**
     * Generates a key starting from a modulus and a generator.
     * It is intended to be used by clients running the DH algorithm.
     *
     * @param modulus   Diffie-Hellman modulus, often referred as p
     * @param generator Diffie-Hellman generator, often referred as g
     * @return AsymmetricKey containing the generated private key
     */
    static AsymmetricKey generateDhKeyFromModulusAndGenerator(BigInteger modulus, BigInteger generator) {
        KeyPairGenerator keyGenerator;
        java.security.KeyFactory keyFactory;
        DHParameterSpec dhParameterSpec = new DHParameterSpec(modulus, generator);
        try {
            keyGenerator = KeyPairGenerator.getInstance("DH");
            keyGenerator.initialize(dhParameterSpec);
            keyFactory = KeyFactory.getInstance("DH");
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerationException("DH key generator not available");
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyGenerationException("Cannot create DH key from input generator and modulus");
        }
        KeyPair pair = keyGenerator.genKeyPair();
        try {
            DHPrivateKeySpec dhPrivateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), DHPrivateKeySpec.class);
            BigInteger privateExponent = (dhPrivateKeySpec.getX());
            return new AsymmetricKey(privateExponent, null, modulus, generator);
        } catch (InvalidKeySpecException e) {
            throw new KeyGenerationException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
        }
    }

    /**
     * Generates a DH or a BS key from scratch with the key size passed as parameter.
     * It is intended to be used by servers and clients running the DH or BS algorithm.
     *
     * @param algorithm a PsiAlgorithm enum. Should be either DH or BS, else throws an exception
     * @param keySize   size of the key
     * @return an AsymmetricKey object which contains the fields that describe the key
     */
    private static AsymmetricKey generateKey(PsiAlgorithm algorithm, int keySize) {
        KeyPairGenerator keyGenerator;
        java.security.KeyFactory keyFactory;
        try {
            String keyType = algorithm.toString();
            if (keyType.equals("BS")) keyType = "RSA";
            keyGenerator = KeyPairGenerator.getInstance(keyType);
            keyFactory = KeyFactory.getInstance(keyType);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerationException(algorithm + " key generator not available");
        }
        keyGenerator.initialize(keySize);
        KeyPair pair = keyGenerator.genKeyPair();

        BigInteger privateExponent;
        BigInteger publicExponent = null;
        BigInteger modulus;
        BigInteger generator = null;

        try {
            switch (algorithm) {
                case BS:
                    RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
                    RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
                    modulus = (rsaPrivateKeySpec.getModulus());
                    privateExponent = (rsaPrivateKeySpec.getPrivateExponent());
                    publicExponent = (rsaPublicKeySpec.getPublicExponent());
                    break;
                case DH:
                    DHPrivateKeySpec dhPrivateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), DHPrivateKeySpec.class);
                    modulus = dhPrivateKeySpec.getP();
                    privateExponent = dhPrivateKeySpec.getX();
                    generator = dhPrivateKeySpec.getG();
                    break;
                default:
                    throw new KeyGenerationException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
            }
        } catch (InvalidKeySpecException e) {
            throw new KeyGenerationException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
        }

        return new AsymmetricKey(privateExponent, publicExponent, modulus, generator);
    }


    /**
     * Generates an ECDH or ECBS key from scratch with the key size passed as parameter.
     * It is intended to be used by servers and clients running the ECDH or ECBS algorithm.
     *
     * @param algorithm a PsiAlgorithm enum. Should be either ECDH or ECBS, else throws an exception
     * @param keySize   size of the key
     * @return an AsymmetricEcKey object which contains the fields that describe the key
     */
    static AsymmetricEcKey generateEcKey(PsiAlgorithm algorithm, int keySize) {
        ECParameterSpec ecSpec;
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyGenerator;
        try {
            keyGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ecSpec = ECNamedCurveTable.getParameterSpec(EllipticCurve.getNameCurve(keySize));
            keyGenerator.initialize(ecSpec, new SecureRandom());
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new KeyGenerationException(algorithm + " key generator not available");
        }
        KeyPair pair = keyGenerator.genKeyPair();

        return new AsymmetricEcKey(
                ((ECPrivateKey)pair.getPrivate()).getD(),
                ((ECPublicKey)pair.getPublic()).getQ());
    }

    /**
     * Generates an elliptic curve key starting from an ECParameterSpec.
     * It is intended to be used by clients running the ECDH algorithm.
     *
     * @param ecSpec ECParameterSpec generated from the selected keySize
     * @return AsymmetricEcKey containing the generated privateD
     */
    static AsymmetricEcKey generateEcDhKeyFromECParameterSpec(ECParameterSpec ecSpec) {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGenerator;
        try {
            keyGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyGenerator.initialize(ecSpec, new SecureRandom());
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new KeyGenerationException("EC key generator not available");
        }
        KeyPair pair = keyGenerator.genKeyPair();

        return new AsymmetricEcKey(
                ((ECPrivateKey)pair.getPrivate()).getD(),
                null);
    }

    static class AsymmetricKey {
        BigInteger privateExponent;
        BigInteger publicExponent;
        BigInteger modulus;
        BigInteger generator;

        AsymmetricKey(BigInteger privateExponent, BigInteger publicExponent, BigInteger modulus, BigInteger generator) {
            this.privateExponent = privateExponent;
            this.publicExponent = publicExponent;
            this.modulus = modulus;
            this.generator = generator;
        }
    }

    static class AsymmetricEcKey{
        BigInteger privateD;
        ECPoint publicQ;

        AsymmetricEcKey(BigInteger privateD, ECPoint publicQ) {
            this.privateD = privateD;
            this.publicQ = publicQ;
        }
    }
}
