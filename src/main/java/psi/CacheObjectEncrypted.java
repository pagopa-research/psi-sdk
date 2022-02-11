package psi;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Cache object used to store the result of the mathematical operations performed in DH and BS (excluding the one
 * producing an additional random value linked to the encrypted one) algorithms.
 */
class CacheObjectEncrypted implements CacheObject, Serializable {

    private static final long serialVersionUID = 1L;

    private BigInteger encryptedValue;

    private CacheObjectEncrypted() {}

    CacheObjectEncrypted(BigInteger encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    BigInteger getEncryptedValue() {
        return encryptedValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CacheObjectEncrypted that = (CacheObjectEncrypted) o;
        return Objects.equals(encryptedValue, that.encryptedValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(encryptedValue);
    }

    @Override
    public String toString() {
        return "EncryptedCacheObject{" +
                "encryptedValue=" + encryptedValue +
                '}';
    }
}
