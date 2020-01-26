/*
 * This file implements a cli UI for the Keccak functionality.
 */

package main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import sha3.Keccak;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * The KeccakCli class enabled the user to call various Keccak
 * derived functions for the command line.
 * @author Spencer Little
 */
public class KeccakCli {

    public static void main(String[] argv) {
        CliArgs cliArgs = new CliArgs();
        try {
            JCommander.newBuilder().addObject(cliArgs).build().parse(argv);
        } catch (ParameterException prx) {
            System.out.println("Mode of operation, input format, and input source must be specified.");
            CliArgs.showHelp();
            System.exit(1);
        }
        if (cliArgs.help) {
            CliArgs.showHelp();
            System.exit(1);
        }

        byte[] outBytes = null;
        if (cliArgs.op.contains("KMACXOF256")) {
            outBytes = processKMAC(cliArgs);
        } else if (cliArgs.op.contains("cSHAKE256")) {
            outBytes = processCSHAKE256(cliArgs);
        } else {
            System.out.println("Unable to recognize mode of operation");
            CliArgs.showHelp();
            System.exit(1);
        }

        System.out.println("Hash: \n" + bytesToHexString(outBytes).toLowerCase());
        if (cliArgs.outputFile != null) {
            writeToFile(outBytes, cliArgs.outputFile);
            System.out.println("Output successfully written to " + cliArgs.outputFile);
        }
    }

    private static byte[] processKMAC(CliArgs args) {
        if (args.bitLen % 8 != 0) {
            System.out.println("Output bit length must be evenly divisible by 8 (bytewise).");
        }
        if (args.keyFilePath == null) {
            System.out.println("KMACXOF mode requires a key file.");
            CliArgs.showHelp();
            System.exit(1);
        }

        byte[] inBytes = readBytes(args);
        byte[] keyBytes = readFile(args.keyFilePath);

        return Keccak.KMACXOF256(keyBytes, inBytes, args.bitLen, args.cString);
    }

    private static byte[] processCSHAKE256(CliArgs args) {
        if (args.bitLen % 8 != 0) {
            System.out.println("Output bit length must be evenly divisible by 8 (bytewise).");
        }
        byte[] inBytes = readBytes(args);

        return Keccak.cSHAKE256(inBytes, args.bitLen, "", args.cString);
    }

    private static byte[] readBytes(CliArgs args) {
        byte[] outBytes = null;
        if (args.inputMode.equals("file")) {
            outBytes = readFile(args.inputSource);
        } else if (args.inputMode.equals("string")) {
            outBytes = args.inputSource.getBytes();
        } else {
            System.out.println("Unable to recognize input mode. Acceptable modes: file, string");
            CliArgs.showHelp();
            System.exit(1);
        }

        return outBytes;
    }

    private static byte[] readFile(String fileName) {
        byte[] outBytes = null;
        try {
            FileInputStream keyIn = new FileInputStream(fileName);
            outBytes = keyIn.readAllBytes();
        } catch (FileNotFoundException fne) {
            System.out.println("Unable to locate file: " + fileName + ", is the URL correct?");
            System.exit(1);
        } catch (IOException iox) {
            System.out.println("Error occurred while reading file: ." + fileName);
            iox.printStackTrace();
            System.exit(1);
        }

        return outBytes;
    }

    private static void writeToFile(byte[] toWrite, String fileName) {
        try {
            FileOutputStream out = new FileOutputStream(fileName);
            out.write(toWrite);
        } catch (FileNotFoundException e) {
            System.out.println("Unable access the specified file, are permissions insufficient? is the URL a directory?");
            System.exit(1);
        } catch (IOException iox) {
            System.out.println("Error occured while writing output to file.");
            iox.printStackTrace();
            System.exit(1);
        }
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
