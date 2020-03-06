/*
 * A cli for the Keccak based cipher functions.
 * Author: Spencer Little
 */

package main.mode;


import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import crypto.keccak.KCrypt;
import main.args.CipherArgs;
import util.DecryptedData;
import util.FileUtilities;

/**
 * Implements a symmetric cipher based on the Keccak functions
 * @author Spencer Little
 * @version 1.0.0
 */
public class KCipher {

    public static void main(String[] argv) {
        CipherArgs args = new CipherArgs();
        try {
            JCommander.newBuilder().addObject(args).build().parse(argv);
        } catch (ParameterException prx) {
            System.out.println("Encrypt/decrypt, a password, and the output URL are required.");
            CipherArgs.showHelp();
            System.exit(1);
        }
        if (args.help) {
            CipherArgs.showHelp();
            System.exit(1);
        }
        validateArgs(args);

        byte[] outBytes;
        boolean chkSumValid = false;
        if (args.encrypt && args.pwdFile != null) {
            outBytes = KCrypt.keccakEncrypt(FileUtilities.readFileBytes(args.pwdFile), FileUtilities.readFileBytes(args.inputURL));
        } else if (args.encrypt) {
            outBytes = KCrypt.keccakEncrypt(args.pwdStr.getBytes(), FileUtilities.readFileBytes(args.inputURL));
        } else if (args.decrypt && args.pwdFile != null) {
            DecryptedData out = KCrypt.keccakDecrypt(FileUtilities.readFileBytes(args.pwdFile), FileUtilities.readFileBytes(args.inputURL));
            chkSumValid = out.isValid();
            outBytes = out.getBytes();
        } else {
            DecryptedData out = KCrypt.keccakDecrypt(args.pwdStr.getBytes(), FileUtilities.readFileBytes(args.inputURL));
            chkSumValid = out.isValid();
            outBytes = out.getBytes();
        }

        if (args.encrypt) {
            FileUtilities.writeBytesToFile(outBytes, args.outputURL);
            System.out.println("Successfully wrote encrypted file to url: " + args.outputURL);
        } else if (args.ignoreTag) {
            FileUtilities.writeBytesToFile(outBytes, args.outputURL);
            System.out.println("Successfully wrote decrypted file to url: " + args.outputURL);
            System.out.println("Authentication tag " + (chkSumValid ? "valid." : "invalid."));
        } else if (!chkSumValid) {
            System.out.println("Warning: Computed MAC did not match transmitted MAC. No data was written to disk. +" +
                    "\nThis behavior can be disabled with the -i flag.");
        } else {
            FileUtilities.writeBytesToFile(outBytes, args.outputURL);
            System.out.println("Successfully wrote decrypted file to url: " + args.outputURL);
            System.out.println("Authentication tag is valid.");
        }

    }

    private static void validateArgs(CipherArgs args) {
        boolean valid = true;
        if ((args.encrypt && args.decrypt) || !(args.encrypt || args.decrypt)) {
            System.out.println("Either encrypt (-e) or decrypt (-d) is required, but not both.");
            valid = false;
        }
        if ((args.pwdFile == null && args.pwdStr == null) || (args.pwdFile != null && args.pwdStr != null)) {
            System.out.println("Either a password file or string is required, but not both.");
            valid = false;
        }
        if (args.outputURL == null) {
            System.out.println("An output URL is required.");
            valid = false;
        }

        if (!valid) {
            System.out.println("Exiting due to inoperable arguments...");
            System.exit(1);
        }
    }
}
