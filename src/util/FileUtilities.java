/*
 * Provides file io utilities to the CLI classes.
 * Author: Spencer Little
 */

package util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Provides basic reading/writing of byte arrays
 * @author Spencer Little
 */
public class FileUtilities {

    public static void writeToFile(byte[] toWrite, String fileName) {
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

    public static byte[] readFile(String fileName) {
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
}
