/*
 * Provides elliptic curve functionality; key generation,
 * asymmetric encryption, and signatures.
 */

package main.mode;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import crypto.EC.ECCrypt;
import crypto.EC.CurvePoint;
import crypto.EC.ECKeyPair;
import crypto.EC.ECSign;
import main.args.ECArgs;
import util.DecryptedData;
import util.FileUtilities;

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
        FileUtilities.writeBytesToFile(ECCrypt.encryptEC(pub, in), args.outUrl);
        System.out.println("Successfully encrypted " + args.dataUrl + " under public key " + args.pubUrl + ". " +
                "\nEncrypted data written to url: " + args.outUrl);
    }

    private static void decryptData(ECArgs args) {
        ECKeyPair key;
        if (args.prvUrl != null) {
            key = ECKeyPair.readPrivateKeyFile(args.prvUrl, args.prvPwd);
            System.out.println("Successfully read private key from " + args.prvUrl);
        } else {
            key = new ECKeyPair(args.genPwd);
            System.out.println("Successfully generated private key from password.");
        }

        byte[] enc = FileUtilities.readFileBytes(args.dataUrl);
        DecryptedData dec = ECCrypt.decryptEC(key.getPrivateScalar(), enc);
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
        FileUtilities.writeBytesToFile(ECSign.schnorrSign(key.getPrivateScalar(), in), args.outUrl);
        System.out.println("Signature generated and written to url: " + args.outUrl);
    }

    private static void validateSignature(ECArgs args) {
        byte[] sig = FileUtilities.readFileBytes(args.sigUrl);
        CurvePoint pub = ECKeyPair.readPubKeyFile(args.pubUrl);
        byte[] msg = FileUtilities.readFileBytes(args.dataUrl);

        if (ECSign.validateSignature(sig, pub, msg)) {
            System.out.println("Signature OK.\n" + "Signature " + args.sigUrl
                    + " of file " + args.dataUrl + " is valid for public key " + args.pubUrl);
        } else {
            System.out.println("Signature NOT VALID.\n" + "Signature " + args.sigUrl
                    + " of file " + args.dataUrl + " is not valid for " + args.pubUrl);
        }
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
            System.out.println("Key generation requires an output url for both the public and private key, and " +
                    "the password used to generate the new EC key pair.");
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.op.equals("encrypt") && (args.pubUrl == null || args.dataUrl == null || args.outUrl == null)) {
            System.out.println("Encryption requires a public key file, an input url, and a url for the cryptogram " +
                    "to be written to.");
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.op.equals("decrypt")
                && ((args.prvUrl == null && args.genPwd == null)
                || (args.prvUrl !=  null && args.prvPwd == null)
                || args.dataUrl == null || args.outUrl == null)) {
            System.out.println("Decryption requires either a private key file and the password " +
                    "under which that file is encrypted or a password to generate the " +
                    "private key, an input url, and a url for the decrypted data to be written to." +
                    " Note that ECUtils accepts a password for key generation or a private key file, but not both.");
            ECArgs.showHelp();
            System.exit(1);
        }
        if (args.op.equals("sign")
                && ((args.prvUrl == null && args.genPwd == null)
                || (args.prvUrl !=  null && args.prvPwd == null)
                || args.dataUrl == null || args.outUrl == null)) {
            System.out.println("Signing a file requires either a password to generate the private key used for signing" +
                    " or a private key file and the password under which that file is encrypted, a url for the file " +
                    "to be signed and an output url to write the signature to. Note that ECUtils accepts a password" +
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
}
