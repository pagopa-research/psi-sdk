package psi.utils;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import psi.exception.PsiServerInitException;
import psi.model.PsiAlgorithm;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerKeyDescriptionFactory;

import javax.crypto.spec.DHPrivateKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class AsymmetricKeyFactory {

    private AsymmetricKeyFactory() {}

    public static PsiServerKeyDescription generateServerKey (PsiAlgorithm algorithm, int keySize) {
         if (algorithm.equals(PsiAlgorithm.BS) || algorithm.equals(PsiAlgorithm.DH)) {
            AsymmetricKey asymmetricKey = generateKey(algorithm, keySize);
            if(algorithm.equals(PsiAlgorithm.BS))
                return PsiServerKeyDescriptionFactory
                        .createBsServerKeyDescription(asymmetricKey.privateKey, asymmetricKey.publicKey, asymmetricKey.modulus);
            else
                return PsiServerKeyDescriptionFactory
                        .createDhServerKeyDescription(asymmetricKey.privateKey, asymmetricKey.modulus);
        }

        if (algorithm.equals(PsiAlgorithm.ECBS) || algorithm.equals(PsiAlgorithm.ECDH)) {
            AsymmetricEcKey asymmetricEcKey = generateEcKey(algorithm, keySize);
            if(algorithm.equals(PsiAlgorithm.ECBS))
                return PsiServerKeyDescriptionFactory
                        .createEcbsServerKeyDescription(asymmetricEcKey.privateKey, asymmetricEcKey.publicKey, asymmetricEcKey.ecSpec);
        }

        throw new PsiServerInitException("Algorithm not supported");

    }

    public static AsymmetricKey generateKey(PsiAlgorithm algorithm, int keySize) {
        KeyPairGenerator keyGenerator;
        java.security.KeyFactory keyFactory;
        try {
            String keyType = algorithm.toString();
            if(keyType.equals("BS")) keyType = "RSA";
            keyGenerator = KeyPairGenerator.getInstance(keyType);
            keyFactory = KeyFactory.getInstance(keyType);
        } catch (NoSuchAlgorithmException e) {
            throw new PsiServerInitException(algorithm + " key generator not available");
        }
        keyGenerator.initialize(keySize);
        KeyPair pair = keyGenerator.genKeyPair();

        BigInteger privateKey = null;
        BigInteger publicKey = null;
        BigInteger modulus = null;

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
                    modulus = (dhPrivateKeySpec.getP());
                    privateKey = (dhPrivateKeySpec.getX());
                    break;
                default:
                    throw new PsiServerInitException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
            }
        } catch (InvalidKeySpecException e) {
            throw new PsiServerInitException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
        }

        return new AsymmetricKey(privateKey, publicKey, modulus);
    }

    public static AsymmetricEcKey generateEcKey(PsiAlgorithm algorithm, int keySize) {
        ECParameterSpec ecSpec;
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyGenerator;
        try {
            keyGenerator = KeyPairGenerator.getInstance("EC", "BC");
            ecSpec = ECNamedCurveTable.getParameterSpec(EllipticCurve.getNameCurve(keySize));
            keyGenerator.initialize(ecSpec, new SecureRandom());
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new PsiServerInitException(algorithm + " key generator not available");
        }
        KeyPair pair = keyGenerator.genKeyPair();

        return new AsymmetricEcKey(
                ((ECPrivateKey)pair.getPrivate()).getD(),
                ((ECPublicKey)pair.getPublic()).getQ(),
                ecSpec
        );
    }

    public static class AsymmetricKey{
        public BigInteger privateKey;
        public BigInteger publicKey;
        public BigInteger modulus;

        AsymmetricKey(BigInteger privateKey, BigInteger publicKey, BigInteger modulus) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.modulus = modulus;
        }
    }

    public static class AsymmetricEcKey{
        public BigInteger privateKey;
        public ECPoint publicKey;
        public ECParameterSpec ecSpec;

        public AsymmetricEcKey(BigInteger privateKey, ECPoint publicKey, ECParameterSpec ecSpec) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.ecSpec = ecSpec;
        }
    }


}
