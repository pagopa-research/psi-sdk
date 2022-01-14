package psi.cache.model;

import java.math.BigInteger;
import java.util.Objects;

public class RandomEncryptedCacheObject implements PsiCacheObject {

    private BigInteger randomValue;

    private BigInteger encryptedValue;

    public RandomEncryptedCacheObject() {}

    public RandomEncryptedCacheObject(BigInteger randomValue, BigInteger encryptedValue) {
        this.randomValue = randomValue;
        this.encryptedValue = encryptedValue;
    }
/*
    public RandomEncryptedCacheObject(String base64) {
        this.initializeFromBase64Representation(base64);
    }

    @Override
    public String getBase64Representation() {
        return Base64EncoderHelper.dtoToBase64(this);
    }

    @Override
    public void initializeFromBase64Representation(String base64) {
        RandomEncryptedCacheObject obj = Base64EncoderHelper.base64ToDto(base64, RandomEncryptedCacheObject.class);
        randomValue = obj.getRandomValue();
        encryptedValue = obj.getEncryptedValue();
    }
*/
    public BigInteger getRandomValue() {
        return randomValue;
    }

    public void setRandomValue(BigInteger randomValue) {
        this.randomValue = randomValue;
    }

    public BigInteger getEncryptedValue() {
        return encryptedValue;
    }

    public void setEncryptedValue(BigInteger encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RandomEncryptedCacheObject that = (RandomEncryptedCacheObject) o;
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
