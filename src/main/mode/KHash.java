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

import java.util.Scanner;

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
        validateArgs(args);

        byte[] outBytes = processInput(args);

        String tag = args.op + " " + args.bitLen + " bits (" + (args.inputUrl == null ? "Console input" : args.inputUrl) + "): \n";
        System.out.println(tag + HexUtilities.bytesToHexString(outBytes).toLowerCase());
        if (args.outputUrl != null) {
            FileUtilities.writeBytesToFile(outBytes, args.outputUrl);
            System.out.println("Output successfully written to " + args.outputUrl);
        }
    }

    private static byte[] processInput(HashArgs args) {
        byte[] outBytes = null;

        if (args.op.contains("KMACXOF256")) {
            outBytes =  Keccak.KMACXOF256(FileUtilities.readFileBytes(args.keyUrl), readBytes(args), args.bitLen, args.cString);
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

    /**
     * Validates the provided HashArgs object by assuring it has a
     * valid combination of parameters
     * @param args the HashArgs object to validate
     */
    private static void validateArgs(HashArgs args) {
        if (args.op.contains("SHA3")
                && !(args.bitLen == 224 || args.bitLen == 256 || args.bitLen == 384 || args.bitLen == 512)) {
            System.out.println("SHA3 supports bit lengths of 224, 256, 384, 512.");
            HashArgs.showHelp();
            System.exit(1);
        } else if (args.op.contains("SHA3") && (!args.cString.equals("") || args.keyUrl != null)) {
            System.out.println("SHA3 does not support customization strings or keys.");
            HashArgs.showHelp();
            System.exit(1);
        } else if (args.op.contains("cSHAKE256") && args.keyUrl != null) {
            System.out.println("cSHAKE256 does not support keys. Did you mean KMACXOF256?");
            HashArgs.showHelp();
            System.exit(1);
        } else if (args.op.contains("KMACXOF256") && args.keyUrl == null) {
            System.out.println("KMACXOF256 requires a key file.");
            HashArgs.showHelp();
            System.exit(1);
        } else if (args.bitLen % 8 != 0) {
            System.out.println("Output bit length must be evenly divisible by 8 (bytewise).");
            System.exit(1);
        }
    }

    /**
     * Reads the user provided input and returns a byte array.
     * @param args the argument object containing cli parameters
     * @return the bytes representing the user input
     */
    private static byte[] readBytes(HashArgs args) {
        byte[] outBytes;
        if (args.inputUrl != null) {
            outBytes = FileUtilities.readFileBytes(args.inputUrl);
        } else {
            outBytes = getUserInput();
        }

        return outBytes;
    }

    /**
     * Gets user input from the console.
     * @return a byte array representing the text the user entered
     */
    private static byte[] getUserInput() {
        Scanner in = new Scanner(System.in);
        StringBuilder str = new StringBuilder();
        String rsp;
        System.out.println("Enter message to be hashed:\n");
        do {
            str.append(in.nextLine());
            System.out.println("More text? y/n");
            rsp = in.next();
            while (!rsp.equalsIgnoreCase("y") && !rsp.equalsIgnoreCase("n")) rsp = in.next();
            in.nextLine();
        } while (rsp.equalsIgnoreCase("y"));

        return str.toString().getBytes();
    }

}
