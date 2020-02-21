/*
 * A set of unit tests covering the ECDHIES functionality.
 */

package test;

import crypto.schnorr.CurvePoint;
import crypto.schnorr.ECKeyPair;
import org.junit.Assert;
import org.junit.Test;

/**
 * A set of unit tests that cover the key generation/storage, asymmetric
 * encryption and signing functions of the Schnorr/ECDHIES classes.
 * @author Spencer Little
 * @version 1.0.0
 */
public class SchnorrTests {

    /**
     * Tests key generation, serialization, storage, and
     * deserialization.
     */
    @Test
    public void testKeyManagement() {
        ECKeyPair origKey = new ECKeyPair("TestPassword");
        origKey.writePubToFile("pubtest");
        origKey.writePrvToEncFile("prvtest");

        ECKeyPair recKey = ECKeyPair.readPrivateKeyFile("prvtest", "TestPassword");
        CurvePoint recPub = ECKeyPair.readPubKeyFile("pubtest");

        Assert.assertEquals(recKey, origKey);
        Assert.assertEquals(recPub, origKey.getPublicCurvePoint());
    }
}
