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

public class EllipticCurve {
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private BigInteger A;
    private BigInteger B;
    private BigInteger P;
    private BigInteger N;
    private ECPoint G;
    private ECCurve ecCurve;
    private String name;

    private ECParameterSpec ecParameterSpec;

    public ECCurve getEcCurve() {
        return ecCurve;
    }

    public String getName() {
        return name;
    }

    public ECParameterSpec getEcParameterSpec() {
        return ecParameterSpec;
    }

    public BigInteger getN() {
        return N;
    }



    public static String getNameCurve(int keySize) {
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

    public static String getPFromNameCurve(String name) {
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

    @Override
    public String toString() {
        return "EllipticCurve{" +
                "A=" + A +
                ", B=" + B +
                ", P=" + P +
                ", N=" + N +
                ", G=" + G +
                '}';
    }

    public EllipticCurve(ECParameterSpec params) {
        ecParameterSpec = params;
        ecCurve = params.getCurve();
        name = getNameCurve(ecCurve.getA().getFieldSize());
        A = ecCurve.getA().toBigInteger();
        B = ecCurve.getB().toBigInteger();
        G = params.getG();
        P = new BigInteger(getPFromNameCurve(name), 16);
        N = params.getN();
    }

    public static ECPoint add(ECPoint p1, ECPoint p2) {
        return p1.add(p2);
    }

    public static ECPoint multiply(ECPoint p, BigInteger k) {
        return p.multiply(k);
    }

    public static ECPoint sub(ECPoint point2D, ECPoint point2D1) {
        return point2D.subtract(point2D1);
    }

    public static BigInteger sqrtP(BigInteger res, BigInteger p) {
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


    public boolean belongs(ECPoint p) {
        return p.getYCoord().toBigInteger().pow(2).subtract(p.getXCoord().toBigInteger().pow(3).add(A.multiply(p.getXCoord().toBigInteger())).add(B)).mod(P).intValue() == 0;
    }

    public ECPoint mapMessage(BigInteger m) {
        if (this.P.compareTo(m) < 0) throw new CustomRuntimeException("need to hash");
        BigInteger k = BigInteger.valueOf(200);
        BigInteger km1 = k.subtract(BigInteger.ONE);
        BigInteger start = m.multiply(k);
        BigInteger y;
        for (BigInteger I = BigInteger.ZERO; I.compareTo(km1) < 0; I = I.add(BigInteger.ONE)) {
            BigInteger x = start.mod(P).add(I).mod(P);
            y = x.modPow(THREE, P).add(A.multiply(x).mod(P)).mod(P).add(B).mod(P);
            if (y.modPow(P.subtract(BigInteger.ONE).multiply(TWO.modInverse(P)).mod(P), P).compareTo(BigInteger.ONE) == 0) {
                BigInteger r = sqrtP(y, P);
                ECPoint res = ecCurve.createPoint(x, r);
                if (!belongs(res)) throw new CustomRuntimeException("Found mapping not on curve");
                return res;
            }

        }
        throw new CustomRuntimeException("Failed to map message");
    }

    private static BigInteger findNonResidue(BigInteger p) {
        int a = 2;
        BigInteger q = (p.subtract(ONE)).divide(TWO);
        while (true) {
            if (BigInteger.valueOf(a).modPow(q, p).compareTo(ONE) != 0) {
                return BigInteger.valueOf(a);
            }
            //If i tried all the numbers in an int and got nothing somthing is wrong... this is taking too long.
            if (a == 0) return null;
            a++;
        }
    }

    /**
     * Calculates square root of res mod p using a start exponent q.
     *
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

    public EncryptedRandomValue generateEncryptedRandomValue(BigInteger inputValue, ECPoint publicKey){
        Random secureRandom = new SecureRandom();
        ECPoint point2DInputValue = mapMessage(inputValue);
        ECPoint randomPointInv;
        ECPoint randomPoint;
        ECPoint encryptedValue;
        BigInteger y;
        do {
            y = new BigInteger(ecParameterSpec.getN().bitCount(), secureRandom).mod(ecParameterSpec.getN());
            randomPoint = multiply(this.G, y);
            randomPointInv = multiply(publicKey, y);
            encryptedValue = add(randomPointInv, point2DInputValue);
        } while(y.compareTo(BigInteger.ZERO) == 0 || randomPoint.isInfinity()|| randomPointInv.isInfinity());

        return new EncryptedRandomValue(encryptedValue, randomPoint);
    }

    public class EncryptedRandomValue{
        private ECPoint encrypted;
        private ECPoint random;

        public EncryptedRandomValue(ECPoint encrypted, ECPoint random) {
            this.encrypted = encrypted;
            this.random = random;
        }

        public ECPoint getEncrypted() {
            return encrypted;
        }

        public ECPoint getRandom() {
            return random;
        }
    }
}
