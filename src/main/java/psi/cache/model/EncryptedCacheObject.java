package psi.cache.model;

import psi.utils.Base64EncoderHelper;

import java.math.BigInteger;

public class EncryptedCacheObject implements CacheObject {

    private BigInteger encryptedValue;

    public EncryptedCacheObject(BigInteger encryptedValue) {
        this.encryptedValue = encryptedValue;
    }

    public EncryptedCacheObject(String base64) {
        this.initializeFromBase64Representation(base64);
    }

    @Override
    public String getBase64Representation() {
        return Base64EncoderHelper.dtoToBase64(this);
    }

    @Override
    public void initializeFromBase64Representation(String base64) {
        EncryptedCacheObject obj = Base64EncoderHelper.base64ToDto(base64, EncryptedCacheObject.class);
        encryptedValue = obj.getEncryptedValue();
    }

    public BigInteger getEncryptedValue() {
        return encryptedValue;
    }

    public void setEncryptedValue(BigInteger encryptedValue) {
        this.encryptedValue = encryptedValue;
    }
}
