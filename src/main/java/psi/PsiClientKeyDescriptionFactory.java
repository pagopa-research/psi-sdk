package psi;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import psi.exception.InvalidPsiClientKeyDescriptionException;
import psi.exception.PsiClientException;

import javax.crypto.spec.DHPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Generates a PsiClientKeyDescription depending on the selected
 * PsiClient implementation, requesting only the variables to be initialized.
 */
public class PsiClientKeyDescriptionFactory {

    private PsiClientKeyDescriptionFactory() {
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the BS algorithm.
     *
     * @param serverPublicExponent String representing the exponent of the server public key
     * @param modulus String representing the modulus of the key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicExponent, String modulus) {
        if (serverPublicExponent == null || modulus == null || serverPublicExponent.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("ServerPublicExponent and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null, serverPublicExponent, modulus);
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the BS algorithm.
     *
     * @param rsaPublicKeySpec the server public key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createBsClientKeyDescription(RSAPublicKeySpec rsaPublicKeySpec) {
        if (rsaPublicKeySpec == null) {
            throw new PsiClientException("RsaPublicKeySpec should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null,
                CustomTypeConverter.convertBigIntegerToString(rsaPublicKeySpec.getPublicExponent()),
                CustomTypeConverter.convertBigIntegerToString(rsaPublicKeySpec.getModulus()));
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the DH algorithm.
     *
     * @param clientPrivateExponent String representing the exponent of the client private key
     * @param modulus String representing the modulus of the key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createDhClientKeyDescription(String clientPrivateExponent, String modulus) {
        if (clientPrivateExponent == null || modulus == null || clientPrivateExponent.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("ClientPrivateExponent and modulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(clientPrivateExponent, null, modulus);
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the DH algorithm.
     *
     * @param dhPrivateKeySpec the client private key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createDhClientKeyDescription(DHPrivateKeySpec dhPrivateKeySpec) {
        if (dhPrivateKeySpec == null) {
            throw new PsiClientException("DhPrivateKeySpec should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(dhPrivateKeySpec.getX()),
                null,
                CustomTypeConverter.convertBigIntegerToString(dhPrivateKeySpec.getP()));
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the ECBS algorithm.
     *
     * @param ecServerPublicQ String representing the Q parameter of the server public key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createEcBsClientKeyDescription(String ecServerPublicQ) {
        if (ecServerPublicQ == null) {
            throw new PsiClientException("EcServerPublicQ should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null, ecServerPublicQ);
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the ECBS algorithm.
     *
     * @param ecPublicKey the server public key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createEcBsClientKeyDescription(ECPublicKey ecPublicKey) {
        if (ecPublicKey == null) {
            throw new PsiClientException("EcPublicKey should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null,
                CustomTypeConverter.convertECPointToString(ecPublicKey.getQ()));
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the ECDH algorithm.
     *
     * @param ecClientPrivateD String representing the D parameter of the client private key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createEcDhClientKeyDescription(String ecClientPrivateD) {
        if (ecClientPrivateD == null) {
            throw new PsiClientException("EcClientPrivateD should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(ecClientPrivateD, null);
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the ECDH algorithm.
     *
     * @param ecPrivateKey the client private key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createEcDhClientKeyDescription(ECPrivateKey ecPrivateKey) {
        if (ecPrivateKey == null) {
            throw new PsiClientException("EcPrivateKey and should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecPrivateKey.getD()),
                null);
    }

    /**
     * Builds a generic PsiClientKeyDescription that can be used to initialize a PsiClient which is compliant
     * with either the BS, DH, ECBS or ECDH algorithm. Differently to other methods of this class,
     * this method receives all the possible input parameter and checks whether it could be valid for any
     * of the supported algorithms.
     *
     * @param clientPrivateExponent String representing the exponent of the client private key
     * @param serverPublicExponent String representing the exponent of the server public key
     * @param modulus String representing the modulus of the key
     * @param ecClientPrivateD the D parameter of the client private key
     * @param ecServerPublicQ the Q parameter of the server public key
     * @return the PsiClientKeyDescription built based on the input parameters
     * @throws InvalidPsiClientKeyDescriptionException whenever the input is not compliant to any
     * PsiClientKeyDescription parameter combination
     */
    public static PsiClientKeyDescription createGenericPsiClientKeyDescription(
            String clientPrivateExponent, String serverPublicExponent, String modulus,
            String ecClientPrivateD, String ecServerPublicQ) throws InvalidPsiClientKeyDescriptionException {
        // Checks if the input combination match to a supported PsiClientKeyDescription combination
        if(!(clientPrivateExponent == null && serverPublicExponent != null && modulus  != null && ecClientPrivateD == null && ecServerPublicQ == null ) && // BS
           !(clientPrivateExponent != null && serverPublicExponent == null && modulus  != null && ecClientPrivateD == null && ecServerPublicQ == null ) && // DH
           !(clientPrivateExponent == null && serverPublicExponent == null && modulus  == null && ecClientPrivateD == null && ecServerPublicQ != null ) && //ECBS
           !(clientPrivateExponent == null && serverPublicExponent == null && modulus  == null && ecClientPrivateD != null && ecServerPublicQ == null ))   //ECDH
            throw new InvalidPsiClientKeyDescriptionException();

        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateExponent(clientPrivateExponent);
        psiClientKeyDescription.setServerPublicExponent(serverPublicExponent);
        psiClientKeyDescription.setModulus(modulus);
        psiClientKeyDescription.setEcClientPrivateD(ecClientPrivateD);
        psiClientKeyDescription.setEcServerPublicQ(ecServerPublicQ);
        return psiClientKeyDescription;
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to load or initialize a DH or BS PsiClient implementation. It
     * is not directly exposed to the user, and it does not perform any check on input parameters.
     *
     * @param clientPrivateExponent the exponent of the client private key
     * @param serverPublicExponent the exponent of the server public key
     * @param modulus the modulus of the key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    private static PsiClientKeyDescription createClientKeyDescription(String clientPrivateExponent, String serverPublicExponent, String modulus) {
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setClientPrivateExponent(clientPrivateExponent);
        psiClientKeyDescription.setServerPublicExponent(serverPublicExponent);
        psiClientKeyDescription.setModulus(modulus);
        return psiClientKeyDescription;
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to load or initialize a ECDH or ECBS PsiClient implementation. It
     * is not directly exposed to the user, and it does not perform any check on input parameters.
     *
     * @param ecClientPrivateD the D parameter of the client private key
     * @param ecServerPublicQ the Q parameter of the server public key
     * @return the PsiServerKeyDescription built based on the input parameters
     */
    private static PsiClientKeyDescription createClientEcKeyDescription(String ecClientPrivateD, String ecServerPublicQ){
        PsiClientKeyDescription psiClientKeyDescription = new PsiClientKeyDescription();
        psiClientKeyDescription.setEcClientPrivateD(ecClientPrivateD);
        psiClientKeyDescription.setEcServerPublicQ(ecServerPublicQ);
        return psiClientKeyDescription;
    }
}
