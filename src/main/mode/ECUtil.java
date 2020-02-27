/*
 * Provides elliptic curve functionality; key generation,
 * asymmetric encryption, and signatures.
 */

package main.mode;

import crypto.keccak.Keccak;
import crypto.schnorr.CurvePoint;
import crypto.schnorr.ECKeyPair;
import util.ArrayUtilities;
import util.DecryptedData;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Provides EC crypto services using the machinery defined
 * in the Schnorr package.
 * @author Spencer Little
 * @version 1.0.0
 */
public class ECUtil {

    /**
     * Encrypts the provided byte array with the EC public key defined by (pub, G)
     * where G is the static public key point defined in ECKeyPair. Encryption is
     * done via the ECDHIES using KMACXOF256 as the underlying primitive.
     * @param pub the public key as a CurvePoint
     * @param in the data to be encrypted
     * @return a cryptogram including Z, a serialized curve point, c, the cipher text, and t the authentication tag
     */
    private byte[] encryptEC(CurvePoint pub, byte[] in) {
        SecureRandom randGen = new SecureRandom();
        byte[] rndBytes = new byte[64];
        randGen.nextBytes(rndBytes);
        BigInteger prvCnst = new BigInteger(rndBytes);
        prvCnst = prvCnst.multiply(BigInteger.valueOf(4L));

        CurvePoint W = pub.scalarMultiply(prvCnst);
        CurvePoint Z = ECKeyPair.G.scalarMultiply(prvCnst);

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
     * @param in the byte array to be decrypted
     * @return the decrypted data in the form of a byte array
     */
    private DecryptedData decryptEC(BigInteger prvScl, byte[] in) {
        CurvePoint Z = CurvePoint.fromByteArray(Arrays.copyOfRange(in, 0, CurvePoint.stdByteLength));
        byte[] msg = Arrays.copyOfRange(in, CurvePoint.stdByteLength, in.length - 64);
        byte[] tag = Arrays.copyOfRange(in, in.length - 64, in.length);

        CurvePoint W = Z.scalarMultiply(prvScl);

        byte[] keys = Keccak.KMACXOF256(W.getX().toByteArray(), new byte[]{}, 1024, "P");
        byte[] key1 = Arrays.copyOfRange(keys, 0, 64);
        byte[] key2 = Arrays.copyOfRange(keys, 64, 128);

        byte[] mask = Keccak.KMACXOF256(key1, new byte[]{}, msg.length*8, "PKE");
        byte[] dec = ArrayUtilities.xorBytes(mask, msg);
        byte[] ctag = Keccak.KMACXOF256(key2, dec, 512, "PKA");

        return new DecryptedData(Arrays.equals(tag, ctag), dec);
    }

    /**
     * Generates a Schnorr signature of the provided byte array.
     * @param pwd the password used to generate the private key of the EC key pair to sign the bytes with
     * @param in the bytes to be signed
     * @return the digital signature in the form of a byte array
     */
    private byte[] schnorrSign(byte[] pwd, byte[] in) {
        ECKeyPair key = new ECKeyPair(pwd);
        byte[] kBytes = Keccak.KMACXOF256(key.getPrivateScalar().toByteArray(), in, 512, "N");
        BigInteger k = new BigInteger(kBytes);

        CurvePoint U = ECKeyPair.G.scalarMultiply(k);
        BigInteger h = new BigInteger(Keccak.KMACXOF256(U.getX().toByteArray(), in, 512, "T"));
        BigInteger z = k.subtract(h.multiply(key.getPrivateScalar())).mod(CurvePoint.P); //TODO: mod r?

        return bigIntsToByteArray(h, z);
    }

    /**
     * Verifies a Schnorr signature of the provided bytes based on the
     * provided public key.
     * @param sgn the schnorr signature, see schnorrSign for details
     * @param pub the public key to valid the signature with
     * @param in the message to be validated
     * @return a boolean value indicating the validity of the signature
     */
    private boolean verifySignature(byte[] sgn, CurvePoint pub, byte[] in) {
        BigInteger[] ints = bigIntsFromByteArray(sgn);
        CurvePoint U = ECKeyPair.G.scalarMultiply(ints[1]).add(pub.scalarMultiply(ints[0]));
        BigInteger h = new BigInteger(Keccak.KMACXOF256(U.getX().toByteArray(), in, 512, "T"));

        return h.equals(ints[0]);
    }

    /**
     * Converts two BigIntegers to a byte array of a standard fixed size
     * (twice the size of P.toByteArray()) by calling toByteArray() on x
     * and y and left padding with bytes as necessary so that x and y each
     * occupy P.toByteArray() bytes.
     * @return an unambiguous byte array representation of this curve point
     */
    private byte[] bigIntsToByteArray(BigInteger x, BigInteger y) {
        byte[] asBytes = new byte[CurvePoint.stdByteLength];
        byte[] xBytes = x.toByteArray(), yBytes = y.toByteArray();
        System.arraycopy(xBytes, 0, asBytes, CurvePoint.stdByteLength / 2 - xBytes.length, xBytes.length);
        System.arraycopy(yBytes, 0, asBytes, asBytes.length - yBytes.length, yBytes.length);
        return asBytes;
    }

    /**
     * Extracts two BigIntegers from the provided byte array. Assumes the BigIntegers
     * have been encoded in the format specified in bigIntsToByteArray.
     * @param in the byte array to decode
     * @return two BigInteger objects parsed from the left and right stdByteLength bytes of in
     */
    private BigInteger[] bigIntsFromByteArray(byte[] in) {
        if (in.length != CurvePoint.stdByteLength) throw new IllegalArgumentException("Provided byte array is not properly formatted");

        int ind = 0;
        while (in[ind] == 0) ind++;
        byte[] xBytes = new byte[CurvePoint.stdByteLength / 2 - ind];
        System.arraycopy(in, ind, xBytes, 0, xBytes.length);

        ind = CurvePoint.stdByteLength / 2;
        while (in[ind] == 0) ind++;
        byte[] yBytes = new byte[in.length - ind];
        System.arraycopy(in, ind, yBytes, 0, yBytes.length);

        //TODO: check if x and y are greater than p

        return new BigInteger[] {new BigInteger(xBytes), new BigInteger(yBytes)};
    }
}
