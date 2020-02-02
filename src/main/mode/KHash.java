/*
 * A cli for the Keccak hash functionality.
 * Author: Spencer Little
 */

package main.mode;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import main.args.HashArgs;
import sha3.Keccak;
import util.FileUtilities;

/**
 * The KeccakCli class enabled the user to call various Keccak
 * derived functions for the command line.
 * @author Spencer Little
 */
public class KHash {

    public static void main(String[] argv) {
        HashArgs args = new HashArgs();
        try {
            JCommander.newBuilder().addObject(args).build().parse(argv);
        } catch (ParameterException prx) {
            System.out.println("Mode of operation, input format, and input source must be specified.");
            HashArgs.showHelp();
            System.exit(1);
        }
        if (args.help) {
            HashArgs.showHelp();
            System.exit(1);
        }

        byte[] outBytes = null;
        if (args.op.contains("KMACXOF256")) {
            outBytes = processKMAC(args);
        } else if (args.op.contains("cSHAKE256")) {
            outBytes = processCSHAKE256(args);
        } else {
            System.out.println("Unable to recognize mode of operation");
            HashArgs.showHelp();
            System.exit(1);
        }

        System.out.println("Hash: \n" + bytesToHexString(outBytes).toLowerCase());
        if (args.outputFile != null) {
            FileUtilities.writeToFile(outBytes, args.outputFile);
            System.out.println("Output successfully written to " + args.outputFile);
        }
    }

    private static byte[] processKMAC(HashArgs args) {
        if (args.bitLen % 8 != 0) {
            System.out.println("Output bit length must be evenly divisible by 8 (bytewise).");
            System.exit(1);
        }
        if (args.keyFilePath == null) {
            System.out.println("KMACXOF mode requires a key file.");
            HashArgs.showHelp();
            System.exit(1);
        }

        byte[] inBytes = readBytes(args);
        byte[] keyBytes = FileUtilities.readFile(args.keyFilePath);

        return Keccak.KMACXOF256(keyBytes, inBytes, args.bitLen, args.cString);
    }

    private static byte[] processCSHAKE256(HashArgs args) {
        if (args.bitLen % 8 != 0) {
            System.out.println("Output bit length must be evenly divisible by 8 (bytewise).");
            System.exit(1);
        }
        byte[] inBytes = readBytes(args);

        return Keccak.cSHAKE256(inBytes, args.bitLen, "", args.cString);
    }

    private static byte[] readBytes(HashArgs args) {
        byte[] outBytes = null;
        if (args.inputMode.equals("file")) {
            outBytes = FileUtilities.readFile(args.inputSource);
        } else if (args.inputMode.equals("string")) {
            outBytes = args.inputSource.getBytes();
        } else {
            System.out.println("Unable to recognize input mode. Acceptable modes: file, string");
            HashArgs.showHelp();
            System.exit(1);
        }

        return outBytes;
    }

    /*
     * Adapted from https://stackoverflow.com/a/9855338/10808192
     */
    private static String bytesToHexString(byte[] in) {
        char[] hexDigits = "0123456789ABCDEF".toCharArray();
        char[] charsHex = new char[in.length * 2];
        for (int i = 0; i < in.length; i++) {
            int j = in[i] & 0xff;
            charsHex[i*2] = hexDigits[j>>>4];
            charsHex[i*2 + 1] = hexDigits[j & 0x0f];
        }

        return new String(charsHex);
    }


}
