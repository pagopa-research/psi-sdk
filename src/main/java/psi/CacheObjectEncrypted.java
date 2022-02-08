package psi;

import java.math.BigInteger;
import java.util.Objects;

class CacheObjectEncrypted extends CacheObject {

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
