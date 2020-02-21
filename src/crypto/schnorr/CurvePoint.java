/*
 * Implements elliptic curve points to enable asymmetric ECDHEIS functionality.
 */

package crypto.schnorr;

import java.io.Serializable;
import java.math.BigInteger;

//TODO: ecDSA: https://tools.ietf.org/html/rfc8032#section-5.1
//TODO: curves: https://tools.ietf.org/html/rfc7748#section-4.1

/**
 * Implements a point on the Edwards curve E_521, defined by
 * E_521: x^2 + y^2 = 1 + d * (x^2) * y^2 where d = -376014
 * @author Spencer Little
 * @version 1.0.0
 */
public class CurvePoint implements Serializable {

    /** The quantity used for modular reduction, a Mersenne prime. */
    private static final BigInteger P = BigInteger.valueOf(2L).pow(521).subtract(BigInteger.ONE);
    /** The quantity used to define the equation of E_521. */
    private static final BigInteger D = BigInteger.valueOf(-376014);
    private final BigInteger x;
    private final BigInteger y;

    /**
     * Initializes a point on the curve with the given x and y parameters.
     * @param x the x coordinate of the point to initialize
     * @param y the y coordinate of the point to initialize
     */
    public CurvePoint(BigInteger x, BigInteger y) {
        //TODO: validation tests are failing during addition
        //if (!isValidPair(x, y)) throw new IllegalArgumentException("The provided x, y pair is not a point on E_521");
        this.x = x;
        this.y = y;
    }

    /**
     * Initializes a point on the curve with the given x and a y that is
     * generated based on the current x with the formula
     * y = sqrt( (1 - x^2) / ( 1 - d * x^2) ) mod p
     * @param x the x coordinate of the point to initialize
     * @param lsb the desired least significant bit of the y coordinate
     */
    public CurvePoint(BigInteger x, boolean lsb) {
        BigInteger a = BigInteger.ONE.subtract(x.pow(2)); // 1 - x^2
        BigInteger b = BigInteger.ONE.subtract(D.multiply(x.pow(2))); // 1 - d * x^2
        BigInteger sqrt = sqrt(a.multiply(b.modInverse(P)), lsb); // sqrt( (1 - x^2) / (1 - dx^2)) mod p
        if (sqrt == null) throw new IllegalArgumentException("No square root of the provided x exists");

        this.x = x;
        this.y = sqrt.mod(P);
    }

    /**
     * Negates the provided point.
     * @param op the point to be negated
     * @return a new curve point (-op.x % p, op.y)
     */
    public static CurvePoint negate(CurvePoint op) {
        return new CurvePoint(op.x.negate().mod(P), op.y);
    }

    /**
     * Multiplies this point by a scalar and returns the result.
     * @param s the scalar to multiply this point by
     * @return this point multiplied by the provided scalar
     */
    public CurvePoint scalarMultiply(BigInteger s) {
        CurvePoint res = ECKeyPair.G.clone();
        int ind = s.bitCount();
        while (--ind >= 0) {
            res = res.add(res);
            if (s.testBit(ind)) res = res.add(ECKeyPair.G);
        }
        return res; // res = this * s
    }

    /**
     * Tests two points for equality by comparing their x and y values.
     * @param o the other point to compare against this
     * @return a boolean indicating whether this == o
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CurvePoint op = (CurvePoint) o;

        return x.equals(op.x) && y.equals(op.y);
    }

    /**
     * Returns a clone of this point with the same x and y values.
     * @return a new CurvePoint with the same x and y pair
     */
    @Override
    public CurvePoint clone() {
        return new CurvePoint(this.x, this.y);
    }

    /**
     * Adds this and op and returns the result. Addition is based on the formula:
     * x = ((x_1 * y_2 + y_2 * x_2) / (1 + d * x_1 * x_2 * y_1 * y_2)) mod p
     * y = ((y_1 * y_2 - x_1 * x_2) / (1 - d * x_1 * x_2 * y_1 * y_2)) mod p
     * @param op the point to be added
     * @return this + op (based on the formula described above)
     */
    private CurvePoint add(CurvePoint op) {
        BigInteger xy  = x.multiply(op.x).multiply(y.multiply(op.y)); // x_1 * x_2 * y_1 * y_2

        BigInteger a = x.multiply(op.y).add(y.multiply(op.x)).mod(P); // a = (x_1 * y_2 + y_2 * x_2) mod p
        BigInteger b = BigInteger.ONE.add(D.multiply(xy)).mod(P); // b = (1 + d * x_1 * x_2 * y_1 * y_2)) mod p
        BigInteger x = a.multiply(b.modInverse(P)).mod(P); // x = (a / b) mod p

        a = y.multiply(op.y).subtract(x.multiply(op.x)).mod(P); // a = (y_1 * y_2 - x_1 * x_2) mod p
        b = BigInteger.ONE.subtract(D.multiply(xy)).mod(P); // b = (1 - d * x_1 * x_2 * y_1 * y_2)) mod p
        BigInteger y = a.multiply(b.modInverse(P)).mod(P); // y = (a / b) mod p

        return new CurvePoint(x, y);
    }

    /**
     * Compute a square root of v mod p with a specified least significant
     * bit, if such a root exists. Provided by lecture notes of Paulo Baretto.
     * @param v the radicand
     * @param lsb the desired least significant bit
     * @return sqaure root of v mod
     */
    private BigInteger sqrt(BigInteger v, boolean lsb) {
        assert (P.testBit(0) && P.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(P.shiftRight(2).add(BigInteger.ONE), P);
        if (r.testBit(0) != lsb) {
            r = P.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(P).signum() == 0) ? r : null; }

    /**
     * Determines whether the provided x and y coordinate pair are a point
     * on the E_521 curve by plugging them into the formula:
     * x^2 + y^2 = 1 + d * (x^2) * y^2 where d = -376014
     * @param x the x coordinate to be tested
     * @param y the y coordinate to be tested
     * @return a boolean flag indicating whether the provided (x, y) pair is a point on E_521
     */
    private boolean isValidPair(BigInteger x, BigInteger y) {
        BigInteger l = x.pow(2).add(y.pow(2)).mod(P); // (x^2 + y^2) mod p
        BigInteger r = BigInteger.ONE.add(D.multiply(x.pow(2).multiply(y.pow(2)))).mod(P); // (1 + d * x^2 * y^2) mod p
        return l.equals(r);
    }
}
