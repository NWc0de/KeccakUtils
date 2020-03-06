/*
 * A set of unit tests covering the ECDHIES functionality.
 */

package test;

import crypto.EC.CurvePoint;
import crypto.EC.ECCrypt;
import crypto.EC.ECKeyPair;
import crypto.EC.ECSign;
import org.junit.Assert;
import org.junit.Test;
import util.DecryptedData;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * A set of unit tests that cover the key generation/storage, asymmetric
 * encryption and signing functions of the Schnorr/ECDHIES classes.
 * @author Spencer Little
 * @version 1.0.0
 */
public class ECTests {

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
    public void testECCrypt() {
        ECKeyPair key;
        SecureRandom gen = new SecureRandom();
        byte[] test = new byte[100];
        for (int i = 0; i < 100; i++) {
            key = new ECKeyPair(randString());
            gen.nextBytes(test);
            byte[] enc = ECCrypt.encryptEC(key.getPublicCurvePoint(), test);
            DecryptedData dec = ECCrypt.decryptEC(key.getPrivateScalar(), enc);
            Assert.assertTrue(dec.isValid());
            Assert.assertArrayEquals(test, dec.getBytes());
        }
    }

    @Test
    public void testSchnorrSignature() {
        ECKeyPair key;
        SecureRandom gen = new SecureRandom();
        byte[] test = new byte[100];
        for (int i = 0; i < 100; i++) {
            key = new ECKeyPair(randString());
            gen.nextBytes(test);
            byte[] sgn = ECSign.schnorrSign(key.getPrivateScalar(), test);
            Assert.assertTrue(ECSign.validateSignature(sgn, key.getPublicCurvePoint(), test));
        }
    }

    private String randString() {
        SecureRandom gen = new SecureRandom();
        StringBuilder rnd = new StringBuilder();
        for (int i = 0; i < gen.nextInt(100); i++) {
            int ch = gen.nextInt(122);
            while (ch < 65) ch = ch + gen.nextInt(122 - ch);
            rnd.append((char) ch);
        }
        return rnd.toString();
    }

}
