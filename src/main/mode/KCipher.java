/*
 * A cli for the Keccak based cipher functions.
 * Author: Spencer Little
 */

package main.mode;


import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import main.args.CipherArgs;
import crypto.keccak.Keccak;
import util.ArrayUtilities;
import util.DecryptedData;
import util.FileUtilities;

import java.security.SecureRandom;
import java.util.Arrays;

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

        byte[] outBytes = null;
        boolean chkSumValid = false;
        if (args.encrypt && args.pwdFile != null) {
            outBytes = keccakEncrypt(FileUtilities.readFileBytes(args.pwdFile), FileUtilities.readFileBytes(args.inputURL));
        } else if (args.encrypt) {
            outBytes = keccakEncrypt(args.pwdStr.getBytes(), FileUtilities.readFileBytes(args.inputURL));
        } else if (args.decrypt && args.pwdFile != null) {
            DecryptedData out = keccakDecrypt(FileUtilities.readFileBytes(args.pwdFile), FileUtilities.readFileBytes(args.inputURL));
            chkSumValid = out.isValid();
            outBytes = out.getBytes();
        } else {
            DecryptedData out = keccakDecrypt(args.pwdStr.getBytes(), FileUtilities.readFileBytes(args.inputURL));
            chkSumValid = out.isValid();
            outBytes = out.getBytes();
        }

        if (args.encrypt) {
            FileUtilities.writeBytesToFile(outBytes, args.outputURL);
            System.out.println("Successfully wrote encrypted file to url: " + args.outputURL);
        } else if (args.ignoreTag) {
            FileUtilities.writeBytesToFile(outBytes, args.outputURL);
            System.out.println("Successfully wrote encrypted file to url: " + args.outputURL);
            System.out.println("Checksum valid: " + chkSumValid);
        } else if (!chkSumValid) {
            System.out.println("Warning: Checksum computed did not match checksum transmitted. No data was written to disk.");
        } else {
            FileUtilities.writeBytesToFile(outBytes, args.outputURL);
            System.out.println("Successfully wrote encrypted file to url: " + args.outputURL);
            System.out.println("Checksum OK.");
        }

    }


    /**
     * Encrypts a byte array under pwd
     * @return a byte array - (initVector || encrypted data || tag (MAC))
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
     * Decrypts a cryptogram under pwd based on the protocl described in keccakEncrypt
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
