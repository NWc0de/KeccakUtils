/*
 * A set of unit tests covering the SHAKE functionality.
 */

package test;

import keccak.Keccak;
import org.junit.Assert;
import org.junit.Test;
import util.HexUtilities;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

/**
 * A set of unit tests covering the SHAKE256 functions. Test vectors
 * follow the format of NIST Cryptographic Validation Program, see
 * https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing#Testing
 */
public class SHAKETest {

    /** The minimum and maximum byte length of the output for the variable length test vectors. */
    private final int MIN_BYTES = 2;
    private final int MAX_BYTES = 250;
    /** Containers for the NIST test vectors. */
    private ArrayList<byte[]> msg = new ArrayList<>();
    private ArrayList<byte[]> hash = new ArrayList<>();
    private ArrayList<Integer> hashLens = new ArrayList<>();
    private byte[] seed;

    @Test
    public void testFixedLengthSHAKE256() {
        readMsgFile("res/shakebytetestvectors/SHAKE256LongMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            Assert.assertArrayEquals(hash.get(i), Keccak.SHAKE256(msg.get(i), 256));
        }
        readMsgFile("res/shakebytetestvectors/SHAKE256ShortMsg.rsp");
        for (int i = 0; i < msg.size(); i++) {
            if (i == 0) msg.set(i, new byte[]{}); // first test is intended to be empty string but 0x00 is read
            Assert.assertArrayEquals(hash.get(i), Keccak.SHAKE256(msg.get(i), 256));
        }
    }

    /* Monte carlo test, see figure 2 in the linked doc for details
     * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf
     */
    @Test
    public void testMonteCarloSHAKE256() {
        readMonteFile("res/shakebytetestvectors/SHAKE256Monte.rsp");
        byte[] msg = seed;
        int outBitLen = MAX_BYTES, range = (MAX_BYTES - MIN_BYTES + 1);
        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 1000; j++) {
                msg = Arrays.copyOf(msg, 16); // last 128 bits of previous output
                msg = Keccak.SHAKE256(msg, outBitLen * 8);
                int rmb = ((msg[msg.length - 2]<<8) & 0xff00) | (msg[msg.length - 1] & 0xff); // 16 right most bits as int
                outBitLen = MIN_BYTES + (rmb % range);
            }
            Assert.assertArrayEquals(hash.get(i), msg);
        }
    }

    @Test
    public void testVariableOutSHAKE256() {
        readVarLenMsgFile("res/shakebytetestvectors/SHAKE256VariableOut.rsp");
        for (int i = 0; i < msg.size(); i++) {
            Assert.assertArrayEquals(hash.get(i), Keccak.SHAKE256(msg.get(i), hashLens.get(i)));
        }
    }

    /**
     * Reads a NIST formatted .rsp message-hash test file, filling hash and msg
     * with the message digests and the messages, respectively, such that
     * SHA3(msg[i]) = hash[i]
     */
    private void readMsgFile(String url) {
        msg.clear(); hash.clear();
        try {
            Scanner in = new Scanner(new File(url));
            while (in.hasNextLine()) {
                String line = in.nextLine();
                if (line.contains("]") || line.equals("") || line.charAt(0) == '#') continue;
                if (line.contains("Msg")) msg.add(HexUtilities.hexStringToBytes(line.split(" ")[2]));
                if (line.contains("Output")) hash.add(HexUtilities.hexStringToBytes(line.split(" ")[2]));
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
            int procd = 0;
            while (in.hasNextLine()) {
                String line = in.nextLine();

                if (procd++ < 9 || line.equals("") || line.charAt(0) == '#') continue;
                if (line.contains("Msg")) seed = HexUtilities.hexStringToBytes(line.split(" ")[2]);
                if (line.contains("Output =")) hash.add(HexUtilities.hexStringToBytes(line.split(" ")[2]));
            }
        } catch (FileNotFoundException fne) {
            System.out.println("Unable to locate file " + url);
            System.exit(1);
        }
    }

    /**
     * Reads a variable output length .rsp file.
     */
    private void readVarLenMsgFile(String url) {
        msg.clear(); hash.clear(); hashLens.clear();
        try {
            Scanner in = new Scanner(new File(url));
            while (in.hasNextLine()) {
                String line = in.nextLine();
                if (line.contains("]") || line.equals("") || line.charAt(0) == '#') continue;
                if (line.contains("Msg")) msg.add(HexUtilities.hexStringToBytes(line.split(" ")[2]));
                if (line.contains("Output =")) hash.add(HexUtilities.hexStringToBytes(line.split(" ")[2]));
                if (line.contains("Outputlen")) hashLens.add(Integer.parseInt(line.split(" ")[2]));
            }
        } catch (FileNotFoundException fne) {
            System.out.println("Unable to locate file " + url);
            System.exit(1);
        } catch (NumberFormatException nfe) {
            System.out.println("Error occured while processing file " + url);
            System.exit(1);
        }
    }
}
