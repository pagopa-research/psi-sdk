package psi.cache.model;

import org.bouncycastle.math.ec.ECPoint;

import java.util.Objects;

public class EncryptedEcCacheObject implements PsiCacheObject {

    private ECPoint encryptedValue;

    public EncryptedEcCacheObject() {}

    public EncryptedEcCacheObject(ECPoint encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    public ECPoint getEncryptedValue() {
        return encryptedValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedEcCacheObject that = (EncryptedEcCacheObject) o;
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
