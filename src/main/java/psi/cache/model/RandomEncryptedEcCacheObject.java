package psi.cache.model;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import psi.utils.CustomTypeConverter;

import java.util.Objects;

public class RandomEncryptedEcCacheObject implements PsiCacheObject {

    private String randomValue;

    private String encryptedValue;

    public RandomEncryptedEcCacheObject() {}

    public RandomEncryptedEcCacheObject(ECPoint randomValue, ECPoint encryptedValue) {
        this.randomValue = CustomTypeConverter.convertECPointToString(randomValue);
        this.encryptedValue = CustomTypeConverter.convertECPointToString(encryptedValue);
    }

    public String getRandomValue() {
        return randomValue;
    }

    public ECPoint getRandomValue(ECCurve curve) {
        return CustomTypeConverter.convertStringToECPoint(curve, this.randomValue);
    }

    public void setRandomValue(String randomValue) {
        this.randomValue = randomValue;
    }

    public String getEncryptedValue() {
        return encryptedValue;
    }

    public ECPoint getEncryptedValue(ECCurve curve) {
        return CustomTypeConverter.convertStringToECPoint(curve, this.encryptedValue);
    }

    public void setEncryptedValue(String encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RandomEncryptedEcCacheObject that = (RandomEncryptedEcCacheObject) o;
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
