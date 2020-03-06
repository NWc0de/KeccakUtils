/*
 * A set of unit tests covering the KMACXOF derived encryption methods.
 */

package test;

import crypto.keccak.KCrypt;
import org.junit.Assert;
import org.junit.Test;
import util.DecryptedData;

import java.security.SecureRandom;

/**
 * A set of unit tests covering the symmetric, KMACXOF256 based,
 * authenticated encryption provided by KCrypt.
 * @author Spencer Little
 * @version 1.0.0
 */
public class KCryptTests {

    @Test
    public void testKCrypt() {
        byte[] test = new byte[10000], pwd = new byte[100];
        SecureRandom gen = new SecureRandom();
        for (int i = 0; i < 1000; i++) {
            gen.nextBytes(pwd);
            gen.nextBytes(test);
            byte[] enc = KCrypt.keccakEncrypt(pwd, test);
            DecryptedData dec = KCrypt.keccakDecrypt(pwd, enc);
            Assert.assertTrue(dec.isValid());
            Assert.assertArrayEquals(test, dec.getBytes());
        }
    }
}
