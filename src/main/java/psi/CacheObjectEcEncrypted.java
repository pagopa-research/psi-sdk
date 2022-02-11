package psi;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.io.Serializable;
import java.util.Arrays;

/**
 * Cache object used to store the result of the mathematical operations performed in ECDH and ECBS (excluding the one
 * producing an additional random value linked to the encrypted one) algorithms.
 */
class CacheObjectEcEncrypted implements CacheObject, Serializable {

    private static final long serialVersionUID = 1L;

    private byte [] encryptedValue;

    private CacheObjectEcEncrypted() {}

    CacheObjectEcEncrypted(ECPoint encryptedValue) {
        this.encryptedValue = encryptedValue.getEncoded(true);
    }

    ECPoint getEncryptedValue(ECCurve curve) {
        return curve.decodePoint(this.encryptedValue);
    }

    static long getSerialVersionUID() {
        return serialVersionUID;
    }

    byte[] getEncryptedValue() {
        return encryptedValue;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CacheObjectEcEncrypted that = (CacheObjectEcEncrypted) o;
        return Arrays.equals(encryptedValue, that.encryptedValue);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(encryptedValue);
    }

    @Override
    public String toString() {
        return "RandomEncryptedEcCacheObject{" +
                "encryptedValue=" + Arrays.toString(encryptedValue) +
                '}';
    }
}
