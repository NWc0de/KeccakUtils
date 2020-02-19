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
     * @param y the y coordinate of the point to initailize
     */
    public CurvePoint(BigInteger x, BigInteger y) {
        if (!isValidPair(x, y)) throw new IllegalArgumentException("The provided x, y pair is not a point on E_521");
        this.x = x;
        this.y = y;
    }

    /**
     * Determines whether the provided x and y coordinate pair are a point
     * on the E_521 curve by plugging them into the formula for the curve:
     * x^2 + y^2 = 1 + d * (x^2) * y^2 where d = -376014
     * @param x the x coordinate to be tested
     * @param y the y coordinate to be tested
     * @return a boolean flag indicating whether the provided (x, y) pair is a point on E_521
     */
    private boolean isValidPair(BigInteger x, BigInteger y) {
        BigInteger l = x.pow(2).add(y.pow(2)); // x^2 + y^2
        BigInteger r = BigInteger.ONE.add(d.multiply(x.pow(2).multiply(y.pow(2)))); // 1 + d * x^2 * y^2
        return l.equals(r);
    }
}
