package psi;

import org.bouncycastle.math.ec.ECPoint;
import psi.exception.InvalidPsiClientKeyDescriptionException;
import psi.exception.PsiClientException;

import java.math.BigInteger;

/**
 * Generates a PsiClientKeyDescription depending on the selected
 * PsiClient implementation, requesting only the variables to be initialized.
 */
public class PsiClientKeyDescriptionFactory {

    private PsiClientKeyDescriptionFactory() {
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the BS algorithm
     *
     * @param serverPublicExponent String representing the exponent of the server public key
     * @param modulus String representing the modulus of the key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createBsClientKeyDescription(String serverPublicExponent, String modulus) {
        if (serverPublicExponent == null || modulus == null || serverPublicExponent.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("Both serverPublicExponent and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null, serverPublicExponent, modulus);
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the BS algorithm
     *
     * BS implementation of the client.
     * @param serverPublicExponent the exponent of the server public key
     * @param modulus the modulus of the key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createBsClientKeyDescription(BigInteger serverPublicExponent, BigInteger modulus) {
        if (serverPublicExponent == null || modulus == null) {
            throw new PsiClientException("Both serverPublicExponent and modulus should not be null when creating a PsiClientDescription for the BS algorithm");
        }
        return createClientKeyDescription(null,
                CustomTypeConverter.convertBigIntegerToString(serverPublicExponent),
                CustomTypeConverter.convertBigIntegerToString(modulus));
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the DH algorithm
     *
     * @param clientPrivateExponent String representing the exponent of the client private key
     * @param modulus String representing the modulus of the key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createDhClientKeyDescription(String clientPrivateExponent, String modulus) {
        if (clientPrivateExponent == null || modulus == null || clientPrivateExponent.isEmpty() || modulus.isEmpty()) {
            throw new PsiClientException("The fields clientPrivateExponent and modulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(clientPrivateExponent, null, modulus);
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the DH algorithm
     *
     * @param clientPrivateExponent the exponent of the client private key
     * @param modulus the modulus of the key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createDhClientKeyDescription(BigInteger clientPrivateExponent, BigInteger modulus) {
        if (clientPrivateExponent == null || modulus == null) {
            throw new PsiClientException("The fields clientPrivateExponent and modulus should not be null when creating a PsiClientDescription for the DH algorithm");
        }
        return createClientKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(clientPrivateExponent),
                null,
                CustomTypeConverter.convertBigIntegerToString(modulus));
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the ECBS algorithm
     *
     * @param ecServerPublicQ String representing the Q parameter of the server public key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createEcBsClientKeyDescription(String ecServerPublicQ) {
        if (ecServerPublicQ == null) {
            throw new PsiClientException("The field ecServerPublicQ should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null, ecServerPublicQ);
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the ECBS algorithm
     *
     * @param ecServerPublicQ the Q parameter of the server public key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createEcBsClientKeyDescription(ECPoint ecServerPublicQ) {
        if (ecServerPublicQ == null) {
            throw new PsiClientException("The field ecServerPublicQ should not be null when creating a PsiClientDescription for the ECBS algorithm");
        }
        return createClientEcKeyDescription(null,
                CustomTypeConverter.convertECPointToString(ecServerPublicQ));
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the ECDH algorithm
     *
     * @param ecClientPrivateD String representing the D parameter of the client private key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createEcDhClientKeyDescription(String ecClientPrivateD) {
        if (ecClientPrivateD == null) {
            throw new PsiClientException("The field ecClientPrivateD should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(ecClientPrivateD, null);
    }

    /**
     * Builds a PsiClientKeyDescription that can be used to initialize a PsiClient for the ECDH algorithm
     * @param ecClientPrivateD the D parameter of the client private key
     * @return the PsiClientKeyDescription built based on the input parameters
     */
    public static PsiClientKeyDescription createEcDhClientKeyDescription(BigInteger ecClientPrivateD) {
        if (ecClientPrivateD == null) {
            throw new PsiClientException("The field ecClientPrivateD and should not be null when creating a PsiClientDescription for the ECDH algorithm");
        }
        return createClientEcKeyDescription(
                CustomTypeConverter.convertBigIntegerToString(ecClientPrivateD),
                null);
    }

    /**
     * Builds a generic PsiClientKeyDescription that can be used to initialize a PsiClient which is compliant
     * with either the BS, DH, ECBS or ECDH algorithm. Differently to other methods of this class,
     * this method receives all the possible input parameter and checks whether it could be valid for any
     * of the supported algorithms,
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
