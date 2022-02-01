package psi.cache.model;

import org.bouncycastle.math.ec.ECPoint;

import java.util.Objects;

public class RandomEncryptedEcCacheObject implements PsiCacheObject {

    private ECPoint randomValue;

    private ECPoint encryptedValue;

    public RandomEncryptedEcCacheObject() {}

    public RandomEncryptedEcCacheObject(ECPoint randomValue, ECPoint encryptedValue) {
        this.randomValue = randomValue;
        this.encryptedValue = encryptedValue;
    }

    public ECPoint getRandomValue() {
        return randomValue;
    }

    public void setRandomValue(ECPoint randomValue) {
        this.randomValue = randomValue;
    }

    public ECPoint getEncryptedValue() {
        return encryptedValue;
    }

    public void setEncryptedValue(ECPoint encryptedValue) {
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
