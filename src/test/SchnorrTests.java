/*
 * A set of unit tests covering the ECDHIES functionality.
 */

package test;

import crypto.keccak.Keccak;
import crypto.schnorr.CurvePoint;
import crypto.schnorr.ECKeyPair;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * A set of unit tests that cover the key generation/storage, asymmetric
 * encryption and signing functions of the Schnorr/ECDHIES classes.
 * @author Spencer Little
 * @version 1.0.0
 */
public class SchnorrTests {

    int STD_BLEN = 129;
    /**
     * Tests key generation, serialization, storage, and
     * deserialization.
     */
    @Test
    public void testKeyStorage() {
        ECKeyPair origKey = new ECKeyPair("TestPassword");
        origKey.writePubToFile("pubtest");
        origKey.writePrvToEncFile("prvtest", "TestPassword");
        origKey.writePrvToEncFile("prvtesttwo", "DifferentPassword");

        ECKeyPair recKey = ECKeyPair.readPrivateKeyFile("prvtest", "TestPassword");
        ECKeyPair recKeyTwo = ECKeyPair.readPrivateKeyFile("prvtesttwo", "DifferentPassword");
        CurvePoint recPub = ECKeyPair.readPubKeyFile("pubtest");

        Assert.assertEquals(recKey, origKey);
        Assert.assertEquals(recKeyTwo, origKey);
        Assert.assertEquals(recPub, origKey.getPublicCurvePoint());
    }

    /**
     * Tests curve point generation and arithmetic.
     */
    @Test
    public void testCurvePointArithmetic() {
        // G + -G = 0
        Assert.assertEquals(CurvePoint.negate(ECKeyPair.G).add(ECKeyPair.G), CurvePoint.ZERO);
        // G + 0 = G
        Assert.assertEquals(ECKeyPair.G.add(CurvePoint.ZERO), ECKeyPair.G);
        // Perform the same tests for 100 randomly generated points
        for (int i = 0; i < 1000; i++) {
            Random gen = new Random();
            BigInteger x = BigInteger.valueOf(gen.nextLong());
            CurvePoint p;
            try {
                p = new CurvePoint(x, gen.nextBoolean());
            } catch (IllegalArgumentException iax) { // the generated x's square root did not exist
                continue;
            }
            Assert.assertEquals(CurvePoint.negate(p).add(p), CurvePoint.ZERO);
            // addition is mod p so initially negative x's will have different, but equivalent mod p, values
            if (x.signum() >= 0) Assert.assertEquals(p.add(CurvePoint.ZERO), p);
        }
    }

    @Test
    public void testCurvePointSerialization() {
        for (int i = 0; i < 1000; i++) {
            Random gen = new Random();
            BigInteger x = BigInteger.valueOf(gen.nextLong());
            CurvePoint p;
            try {
                p = new CurvePoint(x, gen.nextBoolean());
            } catch (IllegalArgumentException iax) { // the generated x's square root did not exist
                continue;
            }
            Assert.assertEquals(p, CurvePoint.fromByteArray(p.toByteArray()));
        }
    }

    @Test
    public void testSignature() {
        ECKeyPair key = new ECKeyPair("tes");
        byte[] test = new byte[100];
        Arrays.fill(test, (byte) 0xff);

        byte[] sgn = schnorrSign(key.getPrivateScalar(), test, key);
        Assert.assertTrue(validateSignature(sgn, key.getPublicCurvePoint(), test));
    }

    /**
     * Generates a Schnorr signature of the provided byte array.
     * @param prvScl the private key of the EC key pair to sign the data with
     * @param in the bytes to be signed
     * @return the digital signature in the form of a byte array
     */
    private byte[] schnorrSign(BigInteger prvScl, byte[] in, ECKeyPair key) {
        byte[] kBytes = Keccak.KMACXOF256(prvScl.toByteArray(), in, 512, "N");
        BigInteger k = new BigInteger(kBytes);
        k = k.multiply(BigInteger.valueOf(4L));

        CurvePoint U = ECKeyPair.G.scalarMultiply(k);
        BigInteger h = new BigInteger(Keccak.KMACXOF256(U.getX().toByteArray(), in, 512, "T"));
        //CurvePoint t1 = ECKeyPair.G.scalarMultiply(prvScl).scalarMultiply(h); // h * s * G
        //CurvePoint t2 = key.getPublicCurvePoint().scalarMultiply(h); // h * V
        //System.out.println("h * V == h * s * G: " + t1.equals(t2)); // h * V == h * s * G
        BigInteger z = k.subtract(h.multiply(prvScl)).mod(CurvePoint.R);

        CurvePoint t3 = ECKeyPair.G.scalarMultiply(z); // z * G
        CurvePoint t4 = ECKeyPair.G.scalarMultiply(k).add(CurvePoint.negate(ECKeyPair.G.scalarMultiply(prvScl.multiply(h)))); // k * G - h * s * G
        System.out.println("zG: " + t3);
        System.out.println("kG - hsG: " + t4);
        System.out.println("zG == kG - hsG: " + t3.equals(t4));

        System.out.println("\nU: " + U);
        CurvePoint U1 = ECKeyPair.G.scalarMultiply(z).add(key.getPublicCurvePoint().scalarMultiply(h));
        System.out.println("U1: " + U1);

        return sigToByteArray(h, z);
    }

    /**
     * Verifies a Schnorr signature of the provided bytes based on the
     * provided public key.
     * @param sgn the Schnorr signature, see schnorrSign for details
     * @param pub the public key to valid the signature with
     * @param in the message to be validated
     * @return a boolean value indicating the validity of the signature
     */
    private boolean validateSignature(byte[] sgn, CurvePoint pub, byte[] in) {
        BigInteger[] ints = sigFromByteArray(sgn);
        CurvePoint U = ECKeyPair.G.scalarMultiply(ints[1]).add(pub.scalarMultiply(ints[0]));
        // System.out.println("U: " + U);
        BigInteger h = new BigInteger(Keccak.KMACXOF256(U.getX().toByteArray(), in, 512, "T"));

        return h.equals(ints[0]);
    }

    /**
     * Converts a Schnorr signature to a byte array of a standard fixed size
     * by calling toByteArray() on h and z. Since h is always 512 bits, it
     * is always the first 64 bytes of the byte array produced.
     * @return an unambiguous byte array representation of this signature (h, z)
     */
    private byte[] sigToByteArray(BigInteger h, BigInteger z) {
        byte[] sigBytes = new byte[STD_BLEN];
        byte[] hBytes = h.toByteArray(), zBytes = z.toByteArray();
        int hPos = STD_BLEN / 2 - hBytes.length, zPos = sigBytes.length - zBytes.length;

        if (h.signum() < 0) Arrays.fill(sigBytes, 0, hPos, (byte) 0xff); // sign extend
        if (z.signum() < 0) Arrays.fill(sigBytes, STD_BLEN / 2, zPos, (byte) 0xff);
        System.arraycopy(hBytes, 0, sigBytes, hPos, hBytes.length);
        System.arraycopy(zBytes, 0, sigBytes, zPos, zBytes.length);

        return sigBytes;
    }

    /**
     * Extracts two BigIntegers from the provided byte array. Assumes the BigIntegers
     * have been encoded in the format specified in bigIntsToByteArray.
     * @param in the byte array to decode
     * @return a Schnorr signature in the form of two BigIntegers (h, z)
     */
    private BigInteger[] sigFromByteArray(byte[] in) {
        if (in.length != STD_BLEN) throw new IllegalArgumentException("Provided byte array is not properly formatted");

        BigInteger h = new BigInteger(Arrays.copyOfRange(in, 0, STD_BLEN / 2));
        BigInteger z = new BigInteger(Arrays.copyOfRange(in, STD_BLEN / 2, STD_BLEN));

        return new BigInteger[] {h, z};
    }

}
