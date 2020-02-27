/*
 * Provides several commonly used array utilities.
 */

package util;

import java.util.Arrays;

/**
 * Provides several common array utilities.
 * @author Spencer Little
 * @version 1.0.0
 */
public class ArrayUtilities {

    /**
     * Merges two bytes arrays. Places elements from b1 before b2 in the
     * new merges array.
     * @param b1 the first array to be merged
     * @param b2 the second array to be merged
     * @return a new array that has all elements of b1 and b2
     */
    public static byte[] mergeByteArrays(byte[] b1, byte[] b2) {
        byte[] mrg = Arrays.copyOf(b1, b1.length + b2.length);
        System.arraycopy(b2, 0, mrg, b1.length, b2.length);
        return mrg;
    }

    /**
     * Xors two byte arrays byte wise.
     * @param b1 the first operand array
     * @param b2 the second operand
     * @return a byte array that is the result of xoring each byte from b1 and b2
     */
    public static byte[] xorBytes(byte[] b1, byte[] b2) {
        if (b1.length != b2.length) throw new IllegalArgumentException("Input arrays are of different lengths");
        byte[] out = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            out[i] = (byte) (b1[i] ^ b2[i]);
        }
        return out;
    }
}
