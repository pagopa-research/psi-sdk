package psi.cache.model;

import psi.utils.Base64EncoderHelper;

import java.math.BigInteger;

public class RandomEncryptedCacheObject implements CacheObject {

    private BigInteger randomValue;

    private BigInteger encryptedValue;


    public RandomEncryptedCacheObject(BigInteger randomValue, BigInteger encryptedValue) {
        this.randomValue = randomValue;
        this.encryptedValue = encryptedValue;
    }

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
}
