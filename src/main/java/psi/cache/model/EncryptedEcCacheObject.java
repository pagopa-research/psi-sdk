package psi.cache.model;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Arrays;

public class EncryptedEcCacheObject extends PsiCacheObject {

    private static final long serialVersionUID = 1L;

    private byte [] encryptedValue;

    public EncryptedEcCacheObject() {}

    public EncryptedEcCacheObject(ECPoint encryptedValue) {
        this.encryptedValue = encryptedValue.getEncoded(true);
    }

    public ECPoint getEncryptedValue(ECCurve curve) {
        return curve.decodePoint(this.encryptedValue);
    }

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    public byte[] getEncryptedValue() {
        return encryptedValue;
    }

    public void setEncryptedValue(byte[] encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EncryptedEcCacheObject that = (EncryptedEcCacheObject) o;
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
