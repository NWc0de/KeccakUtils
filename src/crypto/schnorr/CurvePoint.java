/*
 * Implements elliptic curve points to enable asymmetric ECDHEIS functionality.
 */

package crypto.schnorr;

import java.math.BigInteger;
import java.util.Arrays;

//TODO: ecDSA: https://tools.ietf.org/html/rfc8032#section-5.1
//TODO: curves: https://tools.ietf.org/html/rfc7748#section-4.1

/**
 * Implements a point on the Edwards curve E_521, defined by
 * E_521: x^2 + y^2 = 1 + d * (x^2) * y^2 where d = -376014
 * @author Spencer Little
 * @version 1.0.0
 */
public class CurvePoint {

    /** The neutral element of the curve. */
    public static final CurvePoint ZERO = new CurvePoint(BigInteger.ZERO, BigInteger.ONE);
    /** The quantity used for modular reduction, a Mersenne prime. */
    public static final BigInteger P = BigInteger.valueOf(2L).pow(521).subtract(BigInteger.ONE);
    /** The standard byte length used to represent this point as a byte array. */
    public static final int STD_BLEN = P.toByteArray().length * 2;
    /** A string representation of the value used to compute R. */
    private static final String RSUB = "337554763258501705789107630418782636071904961214051226618635150085779108655765";
    /** The number of points on E_521 is 4r. This quantity is used when computing Schnorr signatures. */
    public static final BigInteger R = BigInteger.valueOf(2L).pow(519).subtract(new BigInteger(RSUB));
    /** The quantity used to define the equation of E_521. */
    private static final BigInteger D = BigInteger.valueOf(-376014);
    /** The x coordinate of this curve point. */
    private final BigInteger x;
    /** The y coordinate of this curve point. */
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
        BigInteger b = BigInteger.ONE.subtract(D.multiply(x.pow(2))); // 1 - d * x^2
        BigInteger sqrt = sqrt(a.multiply(b.modInverse(P)), lsb); // sqrt( (1 - x^2) / (1 - dx^2)) mod p
        if (sqrt == null) throw new IllegalArgumentException("No square root of the provided x exists");

        this.x = x;
        this.y = sqrt.mod(P);
    }

    public BigInteger getX() { return x; }

    /**
     * Negates the provided point.
     * @param op the point to be negated
     * @return a new curve point (-op.x % p, op.y)
     */
    public static CurvePoint negate(CurvePoint op) { return new CurvePoint(op.x.negate().mod(P), op.y); }

    /**
     * Multiplies this point by a scalar and returns the result.
     * @param s the scalar to multiply this point by
     * @return this point multiplied by the provided scalar
     */
    public CurvePoint scalarMultiply(BigInteger s) {
        CurvePoint res = ZERO;
        BigInteger k = s.mod(R); // NOTE: not in spec but necessary
        int ind = k.bitLength();
        while (ind >= 0) {
            res = res.add(res);
            if (k.testBit(ind--)) res = res.add(this);
        }
        return res; // res = this * s
    }

    /**
     * Adds this and op and returns the result. Addition is based on the formula:
     * x = ((x_1 * y_2 + y_2 * x_2) / (1 + d * x_1 * x_2 * y_1 * y_2)) mod p
     * y = ((y_1 * y_2 - x_1 * x_2) / (1 - d * x_1 * x_2 * y_1 * y_2)) mod p
     * @param op the point to be added
     * @return this + op (based on the formula described above)
     */
    public CurvePoint add(CurvePoint op) {
        BigInteger xy  = x.multiply(op.x).multiply(y.multiply(op.y)).mod(P); // x_1 * x_2 * y_1 * y_2 mod p

        BigInteger a = x.multiply(op.y).add(y.multiply(op.x)).mod(P); // a = (x_1 * y_2 + y_1 * x_2) mod p
        BigInteger b = BigInteger.ONE.add(D.multiply(xy)).mod(P); // b = (1 + d * x_1 * x_2 * y_1 * y_2)) mod p
        BigInteger c = a.multiply(b.modInverse(P)).mod(P); // c = (a * b^-1 mod p) mod p = (a / b) mod p

        a = y.multiply(op.y).subtract(x.multiply(op.x)).mod(P); // a = (y_1 * y_2 - x_1 * x_2) mod p
        b = BigInteger.ONE.subtract(D.multiply(xy)).mod(P); // b = (1 - d * x_1 * x_2 * y_1 * y_2)) mod p
        BigInteger d = a.multiply(b.modInverse(P)).mod(P); // d = (a * b^-1 mod p) mod p = (a / b) mod p
        
        return new CurvePoint(c, d);
    }

    /**
     * Converts this CurvePoint to a byte array of a standard fixed size
     * (twice the size of P.toByteArray()) by calling toByteArray() on x
     * and y and left padding with bytes as necessary so that x and y each
     * occupy P.toByteArray() bytes.
     * @return an unambiguous byte array representation of this curve point
     */
    public byte[] toByteArray() {
        byte[] asBytes = new byte[STD_BLEN];
        byte[] xBytes = x.toByteArray(), yBytes = y.toByteArray();
        int xPos = STD_BLEN / 2 - xBytes.length, yPos = asBytes.length - yBytes.length;

        if (x.signum() < 0) Arrays.fill(asBytes, 0, xPos, (byte) 0xff); // sign extend
        if (y.signum() < 0) Arrays.fill(asBytes, STD_BLEN / 2, yPos, (byte) 0xff);
        System.arraycopy(xBytes, 0, asBytes, xPos, xBytes.length);
        System.arraycopy(yBytes, 0, asBytes, yPos, yBytes.length);

        return asBytes;
    }

    /**
     * Generates a CurvePoint from the provided byte array, assuming the
     * byte array is in the format defined in toByteArray().
     * @param pBytes the byte array representing the desired CurvePoint
     * @return a CurvePoint parsed from the byte array in the style defined in toByteArray()
     */
    public static CurvePoint fromByteArray(byte[] pBytes) {
        if (pBytes.length != STD_BLEN) throw new IllegalArgumentException("Provided byte array is not properly formatted");

        BigInteger x = new BigInteger(Arrays.copyOfRange(pBytes, 0, STD_BLEN / 2));
        BigInteger y = new BigInteger(Arrays.copyOfRange(pBytes, STD_BLEN / 2, STD_BLEN));

        return new CurvePoint(x, y);
    }

    /**
     * Returns a string representation of this CurvePoint.
     * @return A string describing the point, (this.x, this.y)
     */
    @Override
    public String toString() {
        return "(" + this.x.toString() + ", " + this.y.toString() + ")";
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
        BigInteger l, r;

        // BigInteger throws exception when computing 1 % p
        if (x.equals(BigInteger.ZERO) && y.equals(BigInteger.ONE)) {
            r = BigInteger.ONE; // (1 + d * 0 * y^z) = 1
            l = BigInteger.ONE; // (0 + 1) = 1
        }
        else {
            l = x.pow(2).add(y.pow(2)).mod(P); // (x^2 + y^2) mod p
            r = BigInteger.ONE.add(D.multiply(x.pow(2).multiply(y.pow(2)))).mod(P); // (1 + d * x^2 * y^2) mod p
        }
        return l.equals(r);
    }
}
