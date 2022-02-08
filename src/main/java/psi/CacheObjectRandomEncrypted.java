package psi;

import java.math.BigInteger;
import java.util.Objects;

class CacheObjectRandomEncrypted extends CacheObject {

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