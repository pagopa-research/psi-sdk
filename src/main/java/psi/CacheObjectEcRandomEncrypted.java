package psi;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.util.Arrays;

class CacheObjectEcRandomEncrypted extends CacheObject {

    private static final long serialVersionUID = 1L;

    private byte [] randomValue;

    private byte [] encryptedValue;

    private CacheObjectEcRandomEncrypted() {}

    CacheObjectEcRandomEncrypted(ECPoint randomValue, ECPoint encryptedValue) {
        this.randomValue = randomValue.getEncoded(true);
        this.encryptedValue = encryptedValue.getEncoded(true);
    }

    ECPoint getRandomValue(ECCurve curve) {
        return curve.decodePoint(this.randomValue);
    }

    ECPoint getEncryptedValue(ECCurve curve) {
        return curve.decodePoint(this.encryptedValue);
    }

    static long getSerialVersionUID() {
        return serialVersionUID;
    }

    byte[] getRandomValue() {
        return randomValue;
    }

    byte[] getEncryptedValue() {
        return encryptedValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CacheObjectEcRandomEncrypted that = (CacheObjectEcRandomEncrypted) o;
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
