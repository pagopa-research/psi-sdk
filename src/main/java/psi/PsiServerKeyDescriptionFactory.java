package psi;

import org.bouncycastle.math.ec.ECPoint;
import psi.exception.PsiServerException;

import java.math.BigInteger;

/**
 * Generates a PsiServerKeyDescription depending on the selected
 * PsiServer implementation, requesting only the variables to be initialized.
 */
public class PsiServerKeyDescriptionFactory {

    private PsiServerKeyDescriptionFactory() {}

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a PsiServer for the
     * BS algorithm.
     *
     * @param privateExponent String representing the exponent of the server private key
     * @param publicExponent String representing the exponent of the server public key
     * @param modulus String representing the modulus of the private and public keys
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    public static PsiServerKeyDescription createBsServerKeyDescription(String privateExponent, String publicExponent, String modulus) {
        if (privateExponent == null || publicExponent == null || modulus == null) {
            throw new PsiServerException("PrivateExponent, publicExponent and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerKeyDescription(privateExponent, publicExponent, modulus, null);
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a PsiServer for the
     * BS algorithm.
     *
     * @param privateExponent the exponent of the server private key
     * @param publicExponent the exponent of the server public key
     * @param modulus the modulus of the private and public keys
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    public static PsiServerKeyDescription createBsServerKeyDescription(BigInteger privateExponent, BigInteger publicExponent, BigInteger modulus) {
        if (privateExponent == null || publicExponent == null || modulus == null) {
            throw new PsiServerException("PrivateExponent, publicExponent and modulus should not be null when creating a PsiServerKeyDescription for the BS algorithm");
        }
        return createServerKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(privateExponent),
                CustomTypeConverter.convertBigIntegerToString(publicExponent),
                CustomTypeConverter.convertBigIntegerToString(modulus),
                null);
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a PsiServer for the
     * DH algorithm.
     *
     * @param privateExponent the exponent of the server private key
     * @param modulus the modulus of the private key
     * @param generator the generator of the private key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    public static PsiServerKeyDescription createDhServerKeyDescription(BigInteger privateExponent, BigInteger modulus, BigInteger generator) {
        if (privateExponent == null || modulus == null || generator == null) {
            throw new PsiServerException("PrivateExponent, modulus and generator should not be null when creating a PsiServerKeyDescription for the DH algorithm");
        }
        return createServerKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(privateExponent),
                null,
                CustomTypeConverter.convertBigIntegerToString(modulus),
                CustomTypeConverter.convertBigIntegerToString(generator));
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a PsiServer for the
     * DH algorithm.
     *
     * @param privateExponent String representing the exponent of the server private key
     * @param modulus String representing the modulus of the private key
     * @param generator String representing the generator of the private key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    public static PsiServerKeyDescription createDhServerKeyDescription(String privateExponent, String modulus, String generator) {
        if (privateExponent == null || modulus == null) {
            throw new PsiServerException("PrivateExponent, modulus and generator should not be null when creating a PsiServerKeyDescription for the DH algorithm");
        }
        return createServerKeyDescription(privateExponent, null, modulus, generator);
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a PsiServer for the
     * ECBS algorithm.
     *
     * @param ecPrivateD String representing the D parameter of the server private key
     * @param ecPublicQ String representing the Q parameter of the server public key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    public static PsiServerKeyDescription createEcBsServerKeyDescription(String ecPrivateD, String ecPublicQ){
        if(ecPrivateD == null || ecPublicQ == null){
            throw new PsiServerException("EcPrivateD and ecPublicQ should not be null when creating a PsiServerKeyDescription for the ECBS algorithm");
        }
        return createServerEcKeyDescription(ecPrivateD, ecPublicQ);
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a PsiServer for the
     * ECBS algorithm.
     *
     * @param ecPrivateD the D parameter of the server private key
     * @param ecPublicQ the Q parameter of the server public key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    public static PsiServerKeyDescription createEcBsServerKeyDescription(BigInteger ecPrivateD, ECPoint ecPublicQ){
        if(ecPrivateD == null || ecPublicQ == null){
            throw new PsiServerException("EcPrivateD and ecPublicQ should not be null when creating a PsiServerKeyDescription for the ECBS algorithm");
        }
        return createServerEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateD),
                CustomTypeConverter.convertECPointToString(ecPublicQ));
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a PsiServer for the
     * ECDH algorithm.
     *
     * @param ecPrivateD String representing the D parameter of the server private key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    public static PsiServerKeyDescription createEcDhServerKeyDescription(String ecPrivateD){
        if(ecPrivateD == null){
            throw new PsiServerException("The field ecPrivateD should not be null when creating a PsiServerKeyDescription for the ECDH algorithm");
        }
        return createServerEcKeyDescription(ecPrivateD, null);
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a PsiServer for the
     * ECDH algorithm.
     *
     * @param ecPrivateD the D parameter of the server private key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    public static PsiServerKeyDescription createEcDhServerKeyDescription(BigInteger ecPrivateD){
        if(ecPrivateD == null){
            throw new PsiServerException("The field ecPrivateD should not be null when creating a PsiServerKeyDescription for the ECDH algorithm");
        }
        return createServerEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateD),
                null);
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a DH or BS PsiServer implementation. It
     * is not directly exposed to the user, and it does not perform any check on input parameters.
     *
     * @param privateExponent the exponent of the server private key
     * @param publicExponent the exponent of the server public key
     * @param modulus the modulus of the private and public keys
     * @param generator the generator of the private and public keys
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    private static PsiServerKeyDescription createServerKeyDescription(String privateExponent, String publicExponent, String modulus, String generator) {
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setPrivateExponent(privateExponent);
        psiServerKeyDescription.setPublicExponent(publicExponent);
        psiServerKeyDescription.setModulus(modulus);
        psiServerKeyDescription.setGenerator(generator);
        return psiServerKeyDescription;
    }

    /**
     * Builds a PsiServerKeyDescription that can be used to load or initialize a ECDH or ECBS PsiServer implementation.
     * It is not directly exposed to the user, and it does not perform any check on input parameters.
     *
     * @param ecPrivateD the D parameter of the server private key
     * @param ecPublicQ the Q parameter of the server public key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    private static PsiServerKeyDescription createServerEcKeyDescription(String ecPrivateD, String ecPublicQ){
        PsiServerKeyDescription psiServerKeyDescription = new PsiServerKeyDescription();
        psiServerKeyDescription.setEcPrivateD(ecPrivateD);
        psiServerKeyDescription.setEcPublicQ(ecPublicQ);
        return psiServerKeyDescription;
    }
}
