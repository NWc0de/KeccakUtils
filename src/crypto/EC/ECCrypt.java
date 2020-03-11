/*
 * Provides the elliptic curve cipher functions.
 */

package crypto.EC;

import crypto.keccak.Keccak;
import util.ArrayUtilities;
import util.DecryptedData;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Provides the elliptic curve encryption functions.
 * @author Spencer Little
 * @version 1.0.0
 */
public class ECCrypt {

    /**
     * Encrypts the provided byte array with the EC public key defined by (pub, G)
     * where G is the static public key point defined in ECKeyPair. Encryption is
     * done via the ECDHIES using KMACXOF256 as the underlying primitive.
     * @param pub the public key as a CurvePoint
     * @param in the data to be encrypted
     * @return a cryptogram including Z, a serialized curve point, c, the cipher text, and t the authentication tag
     */
    public static byte[] encryptEC(CurvePoint pub, byte[] in) {
        SecureRandom randGen = new SecureRandom();
        byte[] rndBytes = new byte[65];
        randGen.nextBytes(rndBytes);
        rndBytes[0] = 0; // assure k is positive
        BigInteger k = new BigInteger(rndBytes);
        k = k.multiply(BigInteger.valueOf(4L));

        CurvePoint W = pub.scalarMultiply(k);
        CurvePoint Z = ECKeyPair.G.scalarMultiply(k);

        byte[] keys = Keccak.KMACXOF256(W.getX().toByteArray(), new byte[]{}, 1024, "P");
        byte[] key1 = Arrays.copyOfRange(keys, 0, 64);
        byte[] key2 = Arrays.copyOfRange(keys, 64, 128);

        byte[] mask = Keccak.KMACXOF256(key1, new byte[]{}, in.length*8, "PKE");
        byte[] enc = ArrayUtilities.xorBytes(mask, in);
        byte[] tag = Keccak.KMACXOF256(key2, in, 512, "PKA");

        return ArrayUtilities.mergeByteArrays(ArrayUtilities.mergeByteArrays(Z.toByteArray(), enc), tag); // (Z || enc || tag)
    }

    /**
     * Decrypts the provided byte array using the private scalar, prvScl. Assumes
     * that the byte array to be decrypted is provided in the format produced
     * by encryptEC, (Z || enc || tag), where Z is the serialized public
     * CurvePoint, enc is the cipher text, and tag is the authentication tag.
     * @param prvScl the private scalar
     * @param enc the byte array to be decrypted
     * @return the decrypted data in the form of a byte array
     */
    public static DecryptedData decryptEC(BigInteger prvScl, byte[] enc) {
        CurvePoint Z = CurvePoint.fromByteArray(Arrays.copyOfRange(enc, 0, CurvePoint.STD_BLEN));
        byte[] msg = Arrays.copyOfRange(enc, CurvePoint.STD_BLEN, enc.length - 64);
        byte[] tag = Arrays.copyOfRange(enc, enc.length - 64, enc.length);

        CurvePoint W = Z.scalarMultiply(prvScl);

        byte[] keys = Keccak.KMACXOF256(W.getX().toByteArray(), new byte[]{}, 1024, "P");
        byte[] key1 = Arrays.copyOfRange(keys, 0, 64);
        byte[] key2 = Arrays.copyOfRange(keys, 64, 128);

        byte[] mask = Keccak.KMACXOF256(key1, new byte[]{}, msg.length*8, "PKE");
        byte[] dec = ArrayUtilities.xorBytes(mask, msg);
        byte[] ctag = Keccak.KMACXOF256(key2, dec, 512, "PKA");

        return new DecryptedData(Arrays.equals(tag, ctag), dec);
    }
}
