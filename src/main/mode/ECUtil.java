/*
 * Provides elliptic curve functionality; key generation,
 * asymmetric encryption, and signatures.
 */

package main.mode;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import crypto.keccak.Keccak;
import crypto.schnorr.CurvePoint;
import crypto.schnorr.ECKeyPair;
import main.args.ECArgs;
import util.ArrayUtilities;
import util.DecryptedData;
import util.FileUtilities;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

/**
 * Provides EC crypto services using the machinery defined
 * in the Schnorr package.
 * @author Spencer Little
 * @version 1.0.0
 */
public class ECUtil {

    /** A list of the valid operations for this module. */
    private static List<String> validOps = Arrays.asList("keygen", "encrypt", "decrypt", "sign", "verify");
    /** The standard byte length for one integer in a Schnorr signature. */
    private static final int STD_BLEN = 512;

    public static void main(String[] argv) {
        ECArgs args = new ECArgs();
        try {
            JCommander.newBuilder().addObject(args).build().parse(argv);
        } catch (ParameterException prx) {
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.help) {
            ECArgs.showHelp();
            System.exit(1);
        }
        validateArgs(args);

        if (args.op.equals("keygen")) {
            genKey(args);
        } else if (args.op.equals("encrypt")) {
            encryptData(args);
        } else if (args.op.equals("decrypt")) {
            decryptData(args);
        } else if (args.op.equals("sign")) {
            signFile(args);
        } else if (args.op.equals("verify")) {
            validateSignature(args);
        }
    }

    private static void genKey(ECArgs args) {
        String filePass = args.prvPwd == null ? args.genPwd : args.prvPwd;
        ECKeyPair key = new ECKeyPair(args.genPwd);
        System.out.println("New EC key pair successfully generated.");
        key.writePrvToEncFile(args.prvUrl, filePass);
        System.out.println("Private key encrypted under password " + filePass + " and written to url: " + args.prvUrl);
        key.writePubToFile(args.pubUrl);
        System.out.println("Public key written to url: " + args.pubUrl);
    }

    private static void encryptData(ECArgs args) {
        CurvePoint pub = ECKeyPair.readPubKeyFile(args.pubUrl);
        byte[] in = FileUtilities.readFileBytes(args.dataUrl);
        FileUtilities.writeBytesToFile(encryptEC(pub, in), args.outUrl);
        System.out.println("Encrypted data successfully written to url: " + args.outUrl);
    }

    private static void decryptData(ECArgs args) {
        ECKeyPair key;
        if (args.prvUrl != null) {
            key = ECKeyPair.readPrivateKeyFile(args.prvUrl, args.prvPwd);
            System.out.println("Successfully read private key from file.");
        } else {
            key = new ECKeyPair(args.genPwd);
            System.out.println("Successfully generated private key from password.");
        }

        byte[] enc = FileUtilities.readFileBytes(args.dataUrl);
        DecryptedData dec = decryptEC(key.getPrivateScalar(), enc);
        System.out.println("Data decryption successful.");

        if (!dec.isValid()) {
            System.out.println("The decrypted data could not be validated, no data was written to disk.");
        } else {
            FileUtilities.writeBytesToFile(dec.getBytes(), args.outUrl);
            System.out.println("Message authentication code OK. Decrypted data written to url: " + args.outUrl);
        }
    }

    private static void signFile(ECArgs args) {
        ECKeyPair key;
        if (args.prvUrl != null) {
            key = ECKeyPair.readPrivateKeyFile(args.prvUrl, args.prvPwd);
            System.out.println("Successfully read private key from file.");
        } else {
            key = new ECKeyPair(args.genPwd);
            System.out.println("Successfully generated private key from password.");
        }

        byte[] in = FileUtilities.readFileBytes(args.dataUrl);
        FileUtilities.writeBytesToFile(schnorrSign(key.getPrivateScalar(), in), args.outUrl);
        System.out.println("Signature generated and written to url: " + args.outUrl);
    }

    private static void validateSignature(ECArgs args) {
        byte[] sig = FileUtilities.readFileBytes(args.sigUrl);
        CurvePoint pub = ECKeyPair.readPubKeyFile(args.pubUrl);
        byte[] msg = FileUtilities.readFileBytes(args.dataUrl);

        if (validateSignature(sig, pub, msg)) {
            System.out.println("Signature OK.");
        } else {
            System.out.println("Signature is not valid.");
        }
    }

    /**
     * Encrypts the provided byte array with the EC public key defined by (pub, G)
     * where G is the static public key point defined in ECKeyPair. Encryption is
     * done via the ECDHIES using KMACXOF256 as the underlying primitive.
     * @param pub the public key as a CurvePoint
     * @param in the data to be encrypted
     * @return a cryptogram including Z, a serialized curve point, c, the cipher text, and t the authentication tag
     */
    private static byte[] encryptEC(CurvePoint pub, byte[] in) {
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
     * @param enc the byte array to be decrypted
     * @return the decrypted data in the form of a byte array
     */
    private static DecryptedData decryptEC(BigInteger prvScl, byte[] enc) {
        CurvePoint Z = CurvePoint.fromByteArray(Arrays.copyOfRange(enc, 0, CurvePoint.stdByteLength));
        byte[] msg = Arrays.copyOfRange(enc, CurvePoint.stdByteLength, enc.length - 64);
        byte[] tag = Arrays.copyOfRange(enc, enc.length - 64, enc.length);

        CurvePoint W = Z.scalarMultiply(prvScl);

        byte[] keys = Keccak.KMACXOF256(W.getX().toByteArray(), new byte[]{}, 1024, "P");
        byte[] key1 = Arrays.copyOfRange(keys, 0, 64);
        byte[] key2 = Arrays.copyOfRange(keys, 64, 128);

        byte[] mask = Keccak.KMACXOF256(key1, new byte[]{}, msg.length*8, "PKE");
        byte[] dec = ArrayUtilities.xorBytes(mask, msg);
        byte[] ctag = Keccak.KMACXOF256(key2, dec, 512, "PKA");

        return new DecryptedData(Arrays.equals(tag, ctag), dec); //TODO no need for DecyptedData, do check here, flag for ignore
    }
    /**
     * Generates a Schnorr signature of the provided byte array.
     * @param prvScl the private key of the EC key pair to sign the data with
     * @param in the bytes to be signed
     * @return the digital signature in the form of a byte array
     */
    private static byte[] schnorrSign(BigInteger prvScl, byte[] in) {
        byte[] kBytes = Keccak.KMACXOF256(prvScl.toByteArray(), in, 512, "N");
        BigInteger k = new BigInteger(kBytes);
        k = k.multiply(BigInteger.valueOf(4L));

        CurvePoint U = ECKeyPair.G.scalarMultiply(k);
        BigInteger h = new BigInteger(Keccak.KMACXOF256(U.getX().toByteArray(), in, 512, "T"));
        BigInteger z = k.subtract(h.multiply(prvScl)).mod(CurvePoint.R);

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
    private static boolean validateSignature(byte[] sgn, CurvePoint pub, byte[] in) {
        BigInteger[] ints = sigFromByteArray(sgn);
        CurvePoint U = ECKeyPair.G.scalarMultiply(ints[1]).add(pub.scalarMultiply(ints[0]));
        BigInteger h = new BigInteger(Keccak.KMACXOF256(U.getX().toByteArray(), in, 512, "T"));

        return h.equals(ints[0]);
    }


    /**
     * Validates the provided ECArgs object by assuring it has a
     * valid combination of parameters
     * @param args the ECArgs object to validate
     */
    private static void validateArgs(ECArgs args) {
        if (!validOps.contains(args.op)) {
            System.out.println("Unable to recognize operation. Valid operations are: keygen, encrypt, decrypt, sign, verify.");
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.op.equals("keygen") && (args.pubUrl == null || args.prvUrl == null || args.genPwd == null)) {
            System.out.println("Key generation requires an output url for both the public and private key,\n and " +
                    "the password used to generate the new EC key pair.");
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.op.equals("encrypt") && (args.pubUrl == null || args.dataUrl == null || args.outUrl == null)) {
            System.out.println("Encryption requires a public key file, an input url, and a url for\n the cryptogram" +
                    "to be written to.");
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.op.equals("decrypt")
                && ((args.prvUrl == null && args.genPwd == null)
                || (args.prvUrl !=  null && args.prvPwd == null)
                || args.dataUrl == null || args.outUrl == null)) {
            System.out.println("Decryption requires a private key file and the password " +
                    "under which \nthat file is enrypted, or a password alone to generate the " +
                    "private key, an input url, and a url for \nthe decrypted data to be written to." +
                    "Note that ECUtils accepts a password for key generation or a private key file, but not both.");
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.op.equals("sign")
                && ((args.prvUrl == null && args.genPwd == null)
                || (args.prvUrl !=  null && args.prvPwd == null)
                || args.dataUrl == null || args.outUrl == null)) {
            System.out.println("Signing a file requires either a password to generate the EC key pair used to signing\n" +
                    " or a private key file and the password under which that file is encrypted, \na url for the file " +
                    "to be signed and an output url to write the signature to. \nNote that ECUtils accepts a password" +
                    " for key generation or a private key file, but not both.");
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.op.equals("validate") && (args.pubUrl == null || args.sigUrl == null || args.dataUrl == null)) {
            System.out.println("Validating a signature requires the url to the public key to be used for validation, " +
                    " the url to the file containing the signature, and the url of the file to be validated.");
            ECArgs.showHelp();
            System.exit(1);
        }
    }

    /**
     * Converts a Schnorr signature to a byte array of a standard fixed size
     * by calling toByteArray() on h and z. Since h is always 512 bits, it
     * is always the first 64 bytes of the byte array produced.
     * @return an unambiguous byte array representation of this signature (h, z)
     */
    private static byte[] sigToByteArray(BigInteger h, BigInteger z) {
        byte[] asBytes = new byte[STD_BLEN];
        byte[] hBytes = h.toByteArray(), zBytes = z.toByteArray();
        int hPos = STD_BLEN / 2 - hBytes.length, zPos = asBytes.length - zBytes.length;

        if (h.signum() < 0) Arrays.fill(asBytes, 0, hPos, (byte) 0xff); // sign extend
        if (z.signum() < 0) Arrays.fill(asBytes, 0, zPos, (byte) 0xff);
        System.arraycopy(hBytes, 0, asBytes, hPos, hBytes.length);
        System.arraycopy(zBytes, 0, asBytes, zPos, zBytes.length);

        return asBytes;
    }

    /**
     * Extracts two BigIntegers from the provided byte array. Assumes the BigIntegers
     * have been encoded in the format specified in bigIntsToByteArray.
     * @param in the byte array to decode
     * @return a Schnorr signature in the form of two BigIntegers (h, z)
     */
    private static BigInteger[] sigFromByteArray(byte[] in) {
        if (in.length != STD_BLEN) throw new IllegalArgumentException("Provided byte array is not properly formatted");

        BigInteger h = new BigInteger(Arrays.copyOfRange(in, 0, STD_BLEN / 2));
        BigInteger z = new BigInteger(Arrays.copyOfRange(in, STD_BLEN / 2, STD_BLEN));

        return new BigInteger[] {h, z};
    }
}
