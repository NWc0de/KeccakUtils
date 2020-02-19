/*
 * A cli for the Keccak hash functionality.
 * Author: Spencer Little
 */

package main.mode;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import main.args.HashArgs;
import crypto.keccak.Keccak;
import util.FileUtilities;
import util.HexUtilities;

/**
 * The KeccakCli class enabled the user to call various Keccak
 * derived functions for the command line.
 * @author Spencer Little
 * @version 1.0.0
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

        byte[] outBytes = processInput(args);

        String tag = args.op + " " + args.bitLen + " bits (" + args.inputSource + "): \n";
        System.out.println(tag + HexUtilities.bytesToHexString(outBytes).toLowerCase());
        if (args.outputFile != null) {
            FileUtilities.writeToFile(outBytes, args.outputFile);
            System.out.println("Output successfully written to " + args.outputFile);
        }
    }

    private static byte[] processInput(HashArgs args) {
        byte[] outBytes = null;
        if (args.bitLen % 8 != 0) {
            System.out.println("Output bit length must be evenly divisible by 8 (bytewise).");
            System.exit(1);
        }
        if (args.op.contains("KMACXOF256")) {
            outBytes = processKMAC(args);
        } else if (args.op.contains("cSHAKE256")) {
            outBytes = Keccak.cSHAKE256(readBytes(args), args.bitLen, "", args.cString);
        } else if (args.op.contains("SHA3")) {
            outBytes = Keccak.SHA3(readBytes(args), args.bitLen);
        } else {
            System.out.println("Unable to recognize mode of operation");
            HashArgs.showHelp();
            System.exit(1);
        }

        return outBytes;
    }

    private static byte[] processKMAC(HashArgs args) {
        if (args.keyFilePath == null) {
            System.out.println("KMACXOF mode requires a key file.");
            HashArgs.showHelp();
            System.exit(1);
        }

        byte[] inBytes = readBytes(args);
        byte[] keyBytes = FileUtilities.readFile(args.keyFilePath);

        return Keccak.KMACXOF256(keyBytes, inBytes, args.bitLen, args.cString);
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

}
