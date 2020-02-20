/*
 * Implements elliptic curve points to enable asymmetric ECDHEIS functionality.
 */

package crypto.schnorr;

import java.math.BigInteger;

/**
 * Implements a point on the Edwards curve E_521, defined by
 * E_521: x^2 + y^2 = 1 + d * (x^2) * y^2 where d = -376014
 * @author Spencer Little
 * @version 1.0.0
 */
public class CurvePoint {

    /** The quantity used for modular reduction, a Mersenne prime. */
    private static final BigInteger p = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);
    /** The quantity used to define the equation of E_521. */
    private static final BigInteger d = BigInteger.valueOf(-376014);
    private final BigInteger x;
    private final BigInteger y;

    /**
     * Initializes a point on the curve with the given x and y parameters.
     * @param x the x coordinate of the point to initialize
     * @param y the y coordinate of the point to initialize
     */
    public CurvePoint(BigInteger x, BigInteger y) {
        if (!isValidPair(x, y)) throw new IllegalArgumentException("The provided x, y pair is not a point on E_521");
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
        BigInteger b = BigInteger.ONE.subtract(d.multiply(x.pow(2))); // 1 - d * x^2
        BigInteger sqrt = sqrt(a.multiply(b.modInverse(p)), lsb); // sqrt( (1 - x^2) / (1 - dx^2))
        if (sqrt == null) throw new IllegalArgumentException("No square root of the provided x exists");

        this.x = x;
        this.y = sqrt.mod(p);
    }

    /**
     * Negates the provided point.
     * @param op the point to be negated
     * @return a new curve point (-op.x % p, op.y)
     */
    public static CurvePoint negate(CurvePoint op) {
        return new CurvePoint(op.x.negate().mod(p), op.y);
    }

    /**
     * Adds this and op and returns the result. Addition is based on the formula:
     * x = ((x_1 * y_2 + y_2 * x_2) / (1 + d * x_1 * x_2 * y_1 * y_2)) mod p
     * y = ((y_1 * y_2 - x_1 * x_2) / (1 - d * x_1 * x_2 * y_1 * y_2)) mod p
     * @param op the point to be added
     * @return this + op (based on the formula described above)
     */
    public CurvePoint add(CurvePoint op) {
        BigInteger xy  = x.multiply(op.x).multiply(y.multiply(op.y)); // x_1 * x_2 * y_1 * y_2

        BigInteger a = x.multiply(op.y).add(y.multiply(op.x)).mod(p); // a = (x_1 * y_2 + y_2 * x_2) mod p
        BigInteger b = BigInteger.ONE.add(d.multiply(xy)).mod(p); // b = (1 + d * x_1 * x_2 * y_1 * y_2)) mod p
        BigInteger x = a.multiply(b.modInverse(p)).mod(p); // x = (a / b) mod p

        a = y.multiply(op.y).subtract(x.multiply(op.x)); // a = (y_1 * y_2 - x_1 * x_2) mod p
        b = BigInteger.ONE.subtract(d.multiply(xy)).mod(p); // b = (1 - d * x_1 * x_2 * y_1 * y_2)) mod p
        BigInteger y = a.multiply(b.modInverse(p)).mod(p); // y = (a / b) mod p

        return new CurvePoint(x, y);
    }

    /**
     * Tests two points for equality by comparing their x and y values.
     * @param o the other point to compare against this
     * @return a boolean indicating whether this == o
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null) return false;
        if (getClass() != o.getClass()) return false;

        CurvePoint op = (CurvePoint) o;

        return x.equals(op.x) && y.equals(op.y);

    }

    /**
     * Compute a square root of v mod p with a specified least significant
     * bit, if such a root exists. Provided by lecture notes of Paulo Baretto.
     * @param v the radicand
     * @param lsb the desired least significant bit
     * @return sqaure root of v mod
     */
    private BigInteger sqrt(BigInteger v, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p); if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null; }

    /**
     * Determines whether the provided x and y coordinate pair are a point
     * on the E_521 curve by plugging them into the formula for the curve:
     * x^2 + y^2 = 1 + d * (x^2) * y^2 where d = -376014
     * @param x the x coordinate to be tested
     * @param y the y coordinate to be tested
     * @return a boolean flag indicating whether the provided (x, y) pair is a point on E_521
     */
    private boolean isValidPair(BigInteger x, BigInteger y) {
        //TODO is this mod p?
        BigInteger l = x.pow(2).add(y.pow(2)); // x^2 + y^2
        BigInteger r = BigInteger.ONE.add(d.multiply(x.pow(2).multiply(y.pow(2)))); // 1 + d * x^2 * y^2
        return l.equals(r);
    }
}
