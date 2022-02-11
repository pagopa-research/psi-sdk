package psi;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import psi.exception.CustomRuntimeException;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

/**
 * This class represents an Elliptic Curve characterized by the following equation.
 * y^2 = x^3 + A*x + B (mod P)
 */

class EllipticCurve {
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private BigInteger a;
    private BigInteger b;
    private BigInteger p;
    private BigInteger n;
    private ECPoint g;
    private ECCurve ecCurve;
    private String name;

    private ECParameterSpec ecParameterSpec;

    ECCurve getEcCurve() {
        return ecCurve;
    }

    String getName() {
        return name;
    }

    ECParameterSpec getEcParameterSpec() {
        return ecParameterSpec;
    }

    BigInteger getN() {
        return n;
    }

    EllipticCurve(ECParameterSpec params) {
        ecParameterSpec = params;
        ecCurve = params.getCurve();
        name = getNameCurve(ecCurve.getA().getFieldSize());
        a = ecCurve.getA().toBigInteger();
        b = ecCurve.getB().toBigInteger();
        g = params.getG();
        p = new BigInteger(getPFromNameCurve(name), 16);
        n = params.getN();
    }

    /**
     * Checks if the input ECPoint belongs to the curve the current elliptic curve.
     * @param p an ECPoint
     * @return true if the input ECPoint belongs to the curve, false otherwise
     */
    private boolean belongs(ECPoint p) {
        return p.getYCoord().toBigInteger().pow(2).subtract(p.getXCoord().toBigInteger().pow(3).add(a.multiply(p.getXCoord().toBigInteger())).add(b)).mod(this.p).intValue() == 0;
    }

    /**
     * Maps the input value to an ECPoint of the current elliptic curve.
     * @param m BigInteger input value
     * @return ECPoint mapping of the input value
     */
    ECPoint mapMessage(BigInteger m) {
        if (this.p.compareTo(m) < 0) throw new CustomRuntimeException("need to hash");
        BigInteger k = BigInteger.valueOf(200);
        BigInteger km1 = k.subtract(BigInteger.ONE);
        BigInteger start = m.multiply(k);
        BigInteger y;
        for (BigInteger I = BigInteger.ZERO; I.compareTo(km1) < 0; I = I.add(BigInteger.ONE)) {
            BigInteger x = start.mod(p).add(I).mod(p);
            y = x.modPow(THREE, p).add(a.multiply(x).mod(p)).mod(p).add(b).mod(p);
            if (y.modPow(p.subtract(BigInteger.ONE).multiply(TWO.modInverse(p)).mod(p), p).compareTo(BigInteger.ONE) == 0) {
                BigInteger r = sqrtP(y, p);
                ECPoint res = ecCurve.createPoint(x, r);
                if (!belongs(res)) throw new CustomRuntimeException("Found mapping not on curve");
                return res;
            }

        }
        throw new CustomRuntimeException("Failed to map message");
    }

    EncryptedRandomValue generateEncryptedRandomValue(BigInteger inputValue, ECPoint ecPoint){
        Random secureRandom = new SecureRandom();
        ECPoint point2DInputValue = mapMessage(inputValue);
        ECPoint randomPointInv;
        ECPoint randomPoint;
        ECPoint encryptedValue;
        BigInteger y;
        do {
            y = new BigInteger(ecParameterSpec.getN().bitCount(), secureRandom).mod(ecParameterSpec.getN());
            randomPoint = multiply(this.g, y);
            randomPointInv = multiply(ecPoint, y);
            encryptedValue = add(randomPointInv, point2DInputValue);
        } while(y.compareTo(BigInteger.ZERO) == 0 || randomPoint.isInfinity()|| randomPointInv.isInfinity());

        return new EncryptedRandomValue(encryptedValue, randomPoint);
    }

    @Override
    public String toString() {
        return "EllipticCurve{" +
                "A=" + a +
                ", B=" + b +
                ", P=" + p +
                ", N=" + n +
                ", G=" + g +
                '}';
    }

    static String getNameCurve(int keySize) {
        if (keySize == 160)
            return "secp160r2";
        else if (keySize == 224)
            return "secp224k1";
        else if (keySize == 256)
            return "prime256v1";
        else if (keySize == 384)
            return "secp384r1";
        else if (keySize == 512 || keySize == 521)
            return "secp521r1";
        else
            throw new CustomRuntimeException("Input key size (" + keySize + ") currently not supported for EC algorithms (ECDH and ECRSA). Supported values are 160, 224, 256, 384, 512 or 521.");
    }

    private static String getPFromNameCurve(String name) {
        if (Objects.equals(name, "secp160r2"))
            return "fffffffffffffffffffffffffffffffeffffac73";
        else if (Objects.equals(name, "secp224k1"))
            return "fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d";
        else if (Objects.equals(name, "prime256v1"))
            return "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        else if (Objects.equals(name, "secp384r1"))
            return "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
        else if (Objects.equals(name, "secp521r1"))
            return "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        else
            throw new CustomRuntimeException("Curve currently not supported.");
    }

    private static ECPoint add(ECPoint p1, ECPoint p2) {
        return p1.add(p2);
    }

    static ECPoint multiply(ECPoint p, BigInteger k) {
        return p.multiply(k);
    }

    static ECPoint sub(ECPoint point2D, ECPoint point2D1) {
        return point2D.subtract(point2D1);
    }

    private static BigInteger sqrtP(BigInteger res, BigInteger p) {
        BigInteger q = (p.subtract(ONE)).divide(TWO);

        while (q.mod(TWO).compareTo(ZERO) == 0) {
            q = q.divide(TWO);
            //if res^q mod p != 1 run the complicated root find
            if (res.modPow(q, p).compareTo(ONE) != 0) {
                return complexSqrtP(res, q, p);
            }

        }
        // Code gets here if res^q mod p were all 1's and now q is odd
        // then root = res^((q+1)/2) mod p
        q = (q.add(ONE)).divide(TWO);
        return res.modPow(q, p);
    }

    private static BigInteger findNonResidue(BigInteger p) {
        int a = 2;
        BigInteger q = (p.subtract(ONE)).divide(TWO);
        while (true) {
            if (BigInteger.valueOf(a).modPow(q, p).compareTo(ONE) != 0) {
                return BigInteger.valueOf(a);
            }
            // Once tested all the possible values of an integer, something is not working
            if (a == 0) return null;
            a++;
        }
    }

    /**
     * Calculates square root of res mod p using a start exponent q.
     * @param res the residue
     * @param q   the prime number
     * @param p   the prime number
     * @return square root of res mod p or null if none can be found
     */
    private static BigInteger complexSqrtP(BigInteger res, BigInteger q, BigInteger p) {
        BigInteger a = findNonResidue(p);
        if (a == null) return null;
        BigInteger t = (p.subtract(ONE)).divide(TWO);
        BigInteger negativePower = t; // a^negativePower mod p = -1 mod p this will be used to get the right power
        //res^q mod p = a^((p-1)/2) mod p

        while (q.mod(TWO).compareTo(ZERO) == 0) {
            q = q.divide(TWO);
            t = t.divide(TWO);
            //check to make sure that the right power was gonnen
            if (res.modPow(q, p).compareTo(a.modPow(t, p)) != 0) {
                //-(a^t mod p) = a^t*a^negativePower mod p = a^t+(negativePower) mod p
                t = t.add(negativePower);
            }
        }
        BigInteger inverseRes = res.modInverse(p);
        //	inverseRes^((q-1)/2)
        q = (q.subtract(ONE)).divide(TWO);
        BigInteger partOne = inverseRes.modPow(q, p);
        //  a^(t/2)
        t = t.divide(TWO);
        BigInteger partTwo = a.modPow(t, p);
        BigInteger root;
        root = partOne.multiply(partTwo);
        root = root.mod(p);
        return root;
    }

    static class EncryptedRandomValue{
        private ECPoint encrypted;
        private ECPoint random;

        EncryptedRandomValue(ECPoint encrypted, ECPoint random) {
            this.encrypted = encrypted;
            this.random = random;
        }

        ECPoint getEncrypted() {
            return encrypted;
        }

        ECPoint getRandom() {
            return random;
        }
    }
}
