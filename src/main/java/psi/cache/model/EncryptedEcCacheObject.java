package psi.cache.model;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import psi.utils.CustomTypeConverter;

import java.util.Objects;

public class EncryptedEcCacheObject implements PsiCacheObject {

    private String encryptedValue;

    public EncryptedEcCacheObject() {}

    public EncryptedEcCacheObject(ECPoint encryptedValue) {
        this.encryptedValue = CustomTypeConverter.convertECPointToString(encryptedValue);
    }

    public String getEncryptedValue() {
        return encryptedValue;
    }

    public ECPoint getEncryptedValue(ECCurve curve) {
        return CustomTypeConverter.convertStringToECPoint(curve, encryptedValue);
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
