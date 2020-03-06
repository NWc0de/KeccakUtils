/*
 * Provides an authenticated encryption scheme based on KMACXOF256.
 */

package crypto.keccak;

import util.ArrayUtilities;
import util.DecryptedData;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Provides an authenticated encryption scheme based on KMACXOF256.
 * @author Spencer Little
 * @version 1.0.0
 */
public class KCrypt {

    /**
     * Encrypts a byte array under pwd
     * @return a cryptogram - (initVector || encrypted data || tag (MAC))
     */
    public static byte[] keccakEncrypt(byte[] pwd, byte[] in) {
        SecureRandom gen = new SecureRandom();
        byte[] rnd = new byte[64];
        gen.nextBytes(rnd);

        byte[] keys = Keccak.KMACXOF256(ArrayUtilities.mergeByteArrays(rnd, pwd), new byte[]{}, 1024, "S");
        byte[] key1 = Arrays.copyOfRange(keys, 0, 64);
        byte[] key2 = Arrays.copyOfRange(keys, 64, 128);

        byte[] mask = Keccak.KMACXOF256(key1, new byte[]{}, in.length*8, "SKE");
        byte[] enc = ArrayUtilities.xorBytes(mask, in);
        byte[] tag = Keccak.KMACXOF256(key2, in, 512, "SKA");

        return ArrayUtilities.mergeByteArrays(ArrayUtilities.mergeByteArrays(rnd, enc), tag); // (rnd || enc || tag)
    }

    /**
     * Decrypts a cryptogram under pwd based on the protocol described in keccakEncrypt
     * @return a DecryptedData object containing the decrypted data and a validity flag (transmitted tag == computed tag)
     */
    public static DecryptedData keccakDecrypt(byte[] pwd, byte[] enc) {
        byte[] rnd = Arrays.copyOfRange(enc, 0, 64);
        byte[] msg = Arrays.copyOfRange(enc, 64, enc.length - 64);
        byte[] tag = Arrays.copyOfRange(enc, enc.length - 64, enc.length);

        byte[] keys = Keccak.KMACXOF256(ArrayUtilities.mergeByteArrays(rnd, pwd), new byte[]{}, 1024, "S");
        byte[] key1 = Arrays.copyOfRange(keys, 0, 64);
        byte[] key2 = Arrays.copyOfRange(keys, 64, 128);

        byte[] mask = Keccak.KMACXOF256(key1, new byte[]{}, msg.length*8, "SKE");
        byte[] dec = ArrayUtilities.xorBytes(mask, msg);
        byte[] ctag = Keccak.KMACXOF256(key2, dec, 512, "SKA");

        return new DecryptedData(Arrays.equals(tag, ctag), dec);
    }
}
