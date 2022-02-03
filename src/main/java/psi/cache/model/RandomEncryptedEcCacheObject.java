package psi.cache.model;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Arrays;

public class RandomEncryptedEcCacheObject extends PsiCacheObject {

    private static final long serialVersionUID = 1L;

    private byte [] randomValue;

    private byte [] encryptedValue;

    public RandomEncryptedEcCacheObject() {}

    public RandomEncryptedEcCacheObject(ECPoint randomValue, ECPoint encryptedValue) {
        this.randomValue = randomValue.getEncoded(true);
        this.encryptedValue = encryptedValue.getEncoded(true);
    }

    public ECPoint getRandomValue(ECCurve curve) {
        return curve.decodePoint(this.randomValue);
    }

    public ECPoint getEncryptedValue(ECCurve curve) {
        return curve.decodePoint(this.encryptedValue);
    }

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    public byte[] getRandomValue() {
        return randomValue;
    }

    public void setRandomValue(byte[] randomValue) {
        this.randomValue = randomValue;
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
        RandomEncryptedEcCacheObject that = (RandomEncryptedEcCacheObject) o;
        return Arrays.equals(randomValue, that.randomValue) &&
                Arrays.equals(encryptedValue, that.encryptedValue);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(randomValue);
        result = 31 * result + Arrays.hashCode(encryptedValue);
        return result;
    }

    @Override
    public String toString() {
        return "RandomEncryptedEcCacheObject{" +
                "randomValue=" + Arrays.toString(randomValue) +
                ", encryptedValue=" + Arrays.toString(encryptedValue) +
                '}';
    }
}
