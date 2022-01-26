package psi.utils;

import psi.client.PsiClient;
import psi.client.PsiClientKeyDescriptionFactory;
import psi.exception.PsiServerInitException;
import psi.model.PsiAlgorithm;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerKeyDescriptionFactory;

import javax.crypto.spec.DHPrivateKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class AsymmetricKeyFactory {

    private AsymmetricKeyFactory() {}

    public static PsiServerKeyDescription generateServerKey (PsiAlgorithm algorithm, int keySize) {
        AsymmetricKey asymmetricKey = generateKey(algorithm, keySize);
        switch (algorithm) {
            case BS:
                return PsiServerKeyDescriptionFactory
                        .createBsServerKeyDescription(asymmetricKey.privateKey, asymmetricKey.publicKey, asymmetricKey.modulus);
            case DH:
                return PsiServerKeyDescriptionFactory
                        .createDhServerKeyDescription(asymmetricKey.privateKey, asymmetricKey.modulus);
            default:
                throw new PsiServerInitException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
        }
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

        String privateKey = null;
        String publicKey = null;
        String modulus = null;

        try {
            switch (algorithm) {
                case BS:
                    RSAPrivateKeySpec rsaPrivateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), RSAPrivateKeySpec.class);
                    RSAPublicKeySpec rsaPublicKeySpec = keyFactory.getKeySpec(pair.getPublic(), RSAPublicKeySpec.class);
                    modulus = (CustomTypeConverter.convertBigIntegerToString(rsaPrivateKeySpec.getModulus()));
                    privateKey = (CustomTypeConverter.convertBigIntegerToString(rsaPrivateKeySpec.getPrivateExponent()));
                    publicKey = (CustomTypeConverter.convertBigIntegerToString(rsaPublicKeySpec.getPublicExponent()));
                    break;
                case DH:
                    DHPrivateKeySpec dhPrivateKeySpec = keyFactory.getKeySpec(pair.getPrivate(), DHPrivateKeySpec.class);
                    modulus = (CustomTypeConverter.convertBigIntegerToString(dhPrivateKeySpec.getP()));
                    privateKey = (CustomTypeConverter.convertBigIntegerToString(dhPrivateKeySpec.getX()));
                    break;
                default:
                    throw new PsiServerInitException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
            }
        } catch (InvalidKeySpecException e) {
            throw new PsiServerInitException("KeySpec is invalid. Verify whether both the input algorithm and key size are correct and compatible.");
        }

        return new AsymmetricKey(privateKey, publicKey, modulus);
    }

    public static class AsymmetricKey{
        public String privateKey;
        public String publicKey;
        public String modulus;

        AsymmetricKey(String privateKey, String publicKey, String modulus) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.modulus = modulus;
        }
    }
}
