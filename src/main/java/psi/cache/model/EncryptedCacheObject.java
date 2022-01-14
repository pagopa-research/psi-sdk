package psi.cache.model;

import java.math.BigInteger;
import java.util.Objects;

public class EncryptedCacheObject implements PsiCacheObject {

    private BigInteger encryptedValue;

    public EncryptedCacheObject() {}

    public EncryptedCacheObject(BigInteger encryptedValue) {
        this.encryptedValue = encryptedValue;
    }


/*
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
*/
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
        EncryptedCacheObject that = (EncryptedCacheObject) o;
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
