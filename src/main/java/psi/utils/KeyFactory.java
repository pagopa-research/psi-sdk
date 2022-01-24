package psi.utils;

import psi.exception.PsiServerInitException;
import psi.model.PsiAlgorithm;
import psi.server.PsiServerKeyDescription;
import psi.server.PsiServerKeyDescriptionFactory;

import javax.crypto.spec.DHPrivateKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class KeyFactory {

    private KeyFactory() {}

    //TODO: should we introduce an intermediate representation?
    public static PsiServerKeyDescription generateKey(PsiAlgorithm algorithm, int keySize) {
        KeyPairGenerator keyGenerator;
        java.security.KeyFactory keyFactory;
        try {
            String keyType = algorithm.toString();
            if(keyType.equals("BS")) keyType = "RSA";
            keyGenerator = KeyPairGenerator.getInstance(keyType);
            keyFactory = java.security.KeyFactory.getInstance(keyType);
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

        return PsiServerKeyDescriptionFactory.createBsServerKeyDescription(privateKey, publicKey, modulus);
    }
}
