/*
 * Enables the generation and maintenance of ECDHIES key pairs.
 */

package crypto.schnorr;

import crypto.keccak.Keccak;
import main.mode.KCipher;
import util.FileUtilities;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Encapsulates an ECDHIES key pair. The public key, (V, G), is
 * a set of two CurvePoints (points on E_521) and the private key,
 * s, is a BigInteger derived from the user provided password.
 * @author Spencer Little
 * @version 1.0.0
 */
public class ECKeyPair {

    /** The static point of the public key. */
    public static final CurvePoint G = new CurvePoint(BigInteger.valueOf(4L), false);
    /** The variable point of the public key, generated based on the provided pwd. */
    private final CurvePoint pub;
    /** The secret key. */
    private final byte[] prv;
    /** The scalar derived from the secret key. */
    private final BigInteger prvScalar;
    /** The password the user provided. */
    private final byte[] pwd;

    /**
     * Generates a new key pair with the provided byte array as the
     * password. The secret key is derived using KMACXOF256 as a
     * generator under the password pwd.
     * @param pwd the password used to derive the secret key
     */
    public ECKeyPair(byte[] pwd) {
        this.pwd = pwd;
        prv = Keccak.KMACXOF256(pwd, new byte[] {}, 512, "K");
        BigInteger s = new BigInteger(prv);
        prvScalar = s.multiply(BigInteger.valueOf(4));
        pub = G.scalarMultiply(s);
    }

    /**
     * Generates a new key pair with the provided String, interpreted
     * as bytes, as the password.
     * @param pwd the password used to derive the secret key.
     */
    public ECKeyPair(String pwd) {
        this(pwd.getBytes());
    }

    /**
     * Returns the dynamic public key CurvePoint.
     * @return the CurvePoint that complements that static public point G
     */
    public CurvePoint getPublicCurvePoint() { return pub; }

    /**
     * Returns the scalar derived from the private key.
     * @return a BigInteger s, the scalar derived from the user provided password
     */
    public BigInteger getPrivateScalar() { return prvScalar; }

    /**
     * Reads the specified public key file and returns the dynamic CurvePoint (pub).
     * @param url the url of the file containing the serialized public key
     * @return a CurvePoint, pub, completing the public key pair (pub, G)
     */
    public static CurvePoint readPubKeyFile(String url) {
        Object pub = FileUtilities.readObjectFromFile(url);
        if (pub.getClass() != CurvePoint.class)
            throw new IllegalStateException("Error occurred during deserialization. Key file may be corrupted.");
        return (CurvePoint) pub;
    }

    /**
     * Reads the specifid private key file and returns a new ECKeyPair with
     * that private key and it's corresponding public key.
     * @param url the url of the file containing the serialized private key
     * @param pwd the password under which the private key was initialized generated
     * @return a new ECKeyPair object containing the private key of the file
     */
    public static ECKeyPair readPrivateKeyFile(String url, byte[] pwd) {
        KCipher.DecryptedData prvBytes = KCipher.keccakDecrypt(pwd, FileUtilities.readFileBytes(url));
        if (!prvBytes.isValid()) {
            System.out.println("Authentication of encrypted private key was unsuccessful.");
            System.out.println("Stored key may be corrupted, perhaps use the password to reinitialize?");
            System.exit(1);
        }

        ECKeyPair genKey = new ECKeyPair(pwd); //TODO: what's the point of storing the private key?
        BigInteger readScalar = new BigInteger(prvBytes.getBytes());
        readScalar = readScalar.multiply(BigInteger.valueOf(4));

        if (!genKey.getPrivateScalar().equals(readScalar)) {
            System.out.print("The private key stored at the provided url does not match ");
            System.out.print("the password provided. No key can be generated");
            System.exit(1);
        }

        return genKey;
    }

    /**
     * Reads a private key file with the password provided as a String.
     */
    public static ECKeyPair readPrivateKeyFile(String url, String pwd) {
        return readPrivateKeyFile(url, pwd.getBytes());
    }

    /**
     * Writes this public key to file by serializing pub. G is not
     * written to file because it is static.
     * @param url the desired file name
     */
    public void writePubToFile(String url) {
        FileUtilities.writeObjectToFile(pub, url);
    }

    /**
     * Writes the private key to file, then encrypts under the password
     * provided during initialization.
     * @param url the desired file name
     */
    public void writePrvToEncFile(String url) {
        FileUtilities.writeBytesToFile(KCipher.keccakEncrypt(pwd, prv), url);
    }

    /**
     * Compares another ECKeyPair object by comparing the
     * public CurvePoint and the private and password byte
     * arrays.
     * @param o the other keyPair to compare with
     * @return true if this == o, false if not
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ECKeyPair ok = (ECKeyPair) o;

        return Arrays.equals(prv, ok.prv)
                && Arrays.equals(pwd, ok.pwd)
                && pub.equals(ok.pub);

    }
}
