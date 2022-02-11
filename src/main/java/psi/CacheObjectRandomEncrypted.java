package psi;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Cache object used to store the results of the client-side mathematical operations performed in BS algorithm.
 * Differently by CacheObjectEncrypted, this object stores an additional random value used and produced during the
 * encryption of its own dataset performed by the BS client.
 */
class CacheObjectRandomEncrypted implements CacheObject, Serializable {

    private static final long serialVersionUID = 1L;

    private BigInteger randomValue;

    private BigInteger encryptedValue;

    private CacheObjectRandomEncrypted() {}

    CacheObjectRandomEncrypted(BigInteger randomValue, BigInteger encryptedValue) {
        this.randomValue = randomValue;
        this.encryptedValue = encryptedValue;
    }

    BigInteger getRandomValue() {
        return randomValue;
    }

    BigInteger getEncryptedValue() {
        return encryptedValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CacheObjectRandomEncrypted that = (CacheObjectRandomEncrypted) o;
        return Objects.equals(randomValue, that.randomValue) &&
                Objects.equals(encryptedValue, that.encryptedValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(randomValue, encryptedValue);
    }

    @Override
    public String toString() {
        return "RandomEncryptedCacheObject{" +
                "randomValue=" + randomValue +
                ", encryptedValue=" + encryptedValue +
                '}';
    }
}
