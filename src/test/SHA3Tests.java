/*
 * A set of unit tests covering the SHA3 functionality.
 */

package test;

import crypto.keccak.Keccak;
import org.junit.Assert;
import org.junit.Test;
import util.HexUtilities;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Scanner;

/**
 * A set of unit tests covering SHA3. Test vectors follow
 * the format of NIST Cryptographic Validation Program, see
 * https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing#Testing
 */
public class SHA3Tests {

    /** Byte arrays to hold the NIST test vectors after being read from a file. */
    private ArrayList<byte[]> msg = new ArrayList<>();
    private ArrayList<byte[]> hash = new ArrayList<>();
    private byte[] seed;

    @Test
    public void testSHA3_224() {
        readMsgFile("res/sha-3bytetestvectors/SHA3_224LongMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            Assert.assertArrayEquals(hash.get(i), Keccak.SHA3(msg.get(i), 224));
        }
        readMsgFile("res/sha-3bytetestvectors/SHA3_224ShortMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            if (i == 0) msg.set(i, new byte[]{}); // first test is intended to be empty string but 0x00 is read
            Assert.assertArrayEquals(hash.get(i), Keccak.SHA3(msg.get(i), 224));
        }
        readMonteFile("res/sha-3bytetestvectors/SHA3_224Monte.rsp");
        byte[] msg = seed;
        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 1000; j++) {
                msg = Keccak.SHA3(msg, 224);
            }
            Assert.assertArrayEquals(hash.get(i), msg);
        }
    }

    @Test
    public void testSHA3_256() {
        readMsgFile("res/sha-3bytetestvectors/SHA3_256LongMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            Assert.assertArrayEquals(hash.get(i), Keccak.SHA3(msg.get(i), 256));
        }
        readMsgFile("res/sha-3bytetestvectors/SHA3_256ShortMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            if (i == 0) msg.set(i, new byte[]{}); // first test is intended to be empty string but 0x00 is read
            Assert.assertArrayEquals(hash.get(i), Keccak.SHA3(msg.get(i), 256));
        }
        readMonteFile("res/sha-3bytetestvectors/SHA3_256Monte.rsp");
        byte[] msg = seed;
        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 1000; j++) {
                msg = Keccak.SHA3(msg, 256);
            }
            Assert.assertArrayEquals(hash.get(i), msg);
        }
    }

    @Test
    public void testSHA3_384() {
        readMsgFile("res/sha-3bytetestvectors/SHA3_384LongMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            Assert.assertArrayEquals(hash.get(i), Keccak.SHA3(msg.get(i), 384));
        }
        readMsgFile("res/sha-3bytetestvectors/SHA3_384ShortMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            if (i == 0) msg.set(i, new byte[]{}); // first test is intended to be empty string but 0x00 is read
            Assert.assertArrayEquals(hash.get(i), Keccak.SHA3(msg.get(i), 384));
        }
        readMonteFile("res/sha-3bytetestvectors/SHA3_384Monte.rsp");
        byte[] msg = seed;
        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 1000; j++) {
                msg = Keccak.SHA3(msg, 384);
            }
            Assert.assertArrayEquals(hash.get(i), msg);
        }
    }

    @Test
    public void testSHA3_512() {
        readMsgFile("res/sha-3bytetestvectors/SHA3_512LongMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            Assert.assertArrayEquals(hash.get(i), Keccak.SHA3(msg.get(i), 512));
        }
        readMsgFile("res/sha-3bytetestvectors/SHA3_512ShortMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            if (i == 0) msg.set(i, new byte[]{}); // first test is intended to be empty string but 0x00 is read
            Assert.assertArrayEquals(hash.get(i), Keccak.SHA3(msg.get(i), 512));
        }
        readMonteFile("res/sha-3bytetestvectors/SHA3_512Monte.rsp");
        byte[] msg = seed;
        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 1000; j++) {
                msg = Keccak.SHA3(msg, 512);
            }
            Assert.assertArrayEquals(hash.get(i), msg);
        }
    }

    /**
     * Reads a NIST formatted .rsp message-hash test file, filling hash and msg
     * with the message digests and the messages, respectively, such that
     * SHA3(msg[i]) = hash[i]
     */
    private void readMsgFile(String url) {
        msg.clear();
        hash.clear();
        try {
            Scanner in = new Scanner(new File(url));
            while (in.hasNextLine()) {
                String line = in.nextLine();
                if (line.equals("") || line.charAt(0) == '#') continue;
                if (line.contains("Msg")) msg.add(HexUtilities.hexStringToBytes(line.split(" ")[2]));
                if (line.contains("MD")) hash.add(HexUtilities.hexStringToBytes(line.split(" ")[2]));
            }
        } catch (FileNotFoundException fne) {
            System.out.println("Unable to locate file " + url);
            System.exit(1);
        }
    }

    /**
     * Reads a NIST formatted .rsp Monte Carlo style file, filling
     * seed with the initial input and hash with the corresponding
     * digests (where ind 0 corresponds to count 0). Ref.
     * https://csrc.nist.gov/CSRC/media/Projects/Hash-Functions/documents/SHA3-KATMCT1.pdf
     */
    private void readMonteFile(String url) {
        hash.clear();
        try {
            Scanner in = new Scanner(new File(url));
            while (in.hasNextLine()) {
                String line = in.nextLine();
                if (line.equals("") || line.charAt(0) == '#') continue;
                if (line.contains("Seed")) seed = HexUtilities.hexStringToBytes(line.split(" ")[2]);
                if (line.contains("MD")) hash.add(HexUtilities.hexStringToBytes(line.split(" ")[2]));
            }
        } catch (FileNotFoundException fne) {
            System.out.println("Unable to locate file " + url);
            System.exit(1);
        }
    }
}
