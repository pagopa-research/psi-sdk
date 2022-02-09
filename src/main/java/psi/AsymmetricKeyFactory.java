package psi;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.exception.KeyGenerationException;
import psi.exception.PsiServerInitException;
import psi.model.PsiAlgorithm;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerKeyDescriptionFactory;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

class AsymmetricKeyFactory {

    private AsymmetricKeyFactory() {}

    static PsiServerKeyDescription generateServerKeyDescription(PsiAlgorithm algorithm, int keySize) {
        if (algorithm.equals(PsiAlgorithm.BS) || algorithm.equals(PsiAlgorithm.DH)) {
            AsymmetricKey asymmetricKey = generateKey(algorithm, keySize);
            if (algorithm.equals(PsiAlgorithm.BS))
                return PsiServerKeyDescriptionFactory
                        .createBsServerKeyDescription(asymmetricKey.privateKey, asymmetricKey.publicKey, asymmetricKey.modulus);
            else
                return PsiServerKeyDescriptionFactory
                        .createDhServerKeyDescription(asymmetricKey.privateKey, asymmetricKey.modulus, asymmetricKey.generator);
        }

        if (algorithm.equals(PsiAlgorithm.ECBS) || algorithm.equals(PsiAlgorithm.ECDH)) {
            AsymmetricEcKey asymmetricEcKey = generateEcKey(algorithm, keySize);
            if(algorithm.equals(PsiAlgorithm.ECBS))
                return PsiServerKeyDescriptionFactory
                        .createEcBsServerKeyDescription(asymmetricEcKey.privateKey, asymmetricEcKey.publicKey);
            else
                return PsiServerKeyDescriptionFactory
                        .createEcDhServerKeyDescription(asymmetricEcKey.privateKey);
        }

        throw new PsiServerInitException("Algorithm not supported");
    }

    /**
     * Method that can be used to generate a key starting from a modulus and a generator.
     * It is intended to be used by clients running the DH algorithm
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
            BigInteger privateKey = (dhPrivateKeySpec.getX());
            return new AsymmetricKey(privateKey, null, modulus, generator);
        } catch (InvalidKeySpecException e) {
            throw new KeyGenerationException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
        }
    }

    /**
     * Method that generates a DH or a BS key from scratch with the key size passed as parameter
     * It is intended to be used servers running the BS or RSA algorithms.
     *
     * @param algorithm an PsiAlgorithm enum. Should be either DH or BS, else throws an exception
     * @param keySize   size of the key
     * @return an AsymmetricKey object which contains the fields that describe the key
     */
    static AsymmetricKey generateKey(PsiAlgorithm algorithm, int keySize) {
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

        BigInteger privateKey;
        BigInteger publicKey = null;
        BigInteger modulus;
        BigInteger generator = null;

        try {
            switch (algorithm) {
                case BS:
                    RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
                    RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
                    modulus = (rsaPrivateKeySpec.getModulus());
                    privateKey = (rsaPrivateKeySpec.getPrivateExponent());
                    publicKey = (rsaPublicKeySpec.getPublicExponent());
                    break;
                case DH:
                    DHPrivateKeySpec dhPrivateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), DHPrivateKeySpec.class);
                    modulus = dhPrivateKeySpec.getP();
                    privateKey = dhPrivateKeySpec.getX();
                    generator = dhPrivateKeySpec.getG();
                    break;
                default:
                    throw new KeyGenerationException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
            }
        } catch (InvalidKeySpecException e) {
            throw new KeyGenerationException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
        }

        return new AsymmetricKey(privateKey, publicKey, modulus, generator);
    }

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
                ((ECPublicKey)pair.getPublic()).getQ(),
                ecSpec
        );
    }

    static class AsymmetricKey{
        BigInteger privateKey;
        BigInteger publicKey;
        BigInteger modulus;
        BigInteger generator;

        AsymmetricKey(BigInteger privateKey, BigInteger publicKey, BigInteger modulus, BigInteger generator) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.modulus = modulus;
            this.generator = generator;
        }
    }

    static class AsymmetricEcKey{
        BigInteger privateKey;
        ECPoint publicKey;
        ECParameterSpec ecSpec;

        AsymmetricEcKey(BigInteger privateKey, ECPoint publicKey, ECParameterSpec ecSpec) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.ecSpec = ecSpec;
        }
    }
}
