/*
 * Allows strings of ASCII characters representing hex values to be translated
 * to byte arrays and vice versa.
 */

package util;

/**
 * Provides several utility method for translating ASCII hex strings
 * to byte arrays vice versa.
 * @author Spencer Little
 * @version 1.0.0
 */
public class HexUtilities {

    /**
     * Returns a hexadecimal representation of the byte array in
     * String form.
     * Adapted from https://stackoverflow.com/a/9855338/10808192
     */
    public static String bytesToHexString(byte[] in) {
        char[] hexDigits = "0123456789abcdef".toCharArray();
        char[] charsHex = new char[in.length * 2];
        for (int i = 0; i < in.length; i++) {
            int j = in[i] & 0xff;
            charsHex[i*2] = hexDigits[j>>>4];
            charsHex[i*2 + 1] = hexDigits[j & 0x0f];
        }

        return new String(charsHex);
    }

    /**
     * Translates a String of hex digits to a byte array. Assumes
     * the hex String is continuous and contains only hex digits.
     */
    public static byte[] hexStringToBytes(String hex) {
        byte[] out = new byte[hex.length() % 2 == 0 ? hex.length()/2 : hex.length()/2 + 1];
        char[] chs = hex.toCharArray();
        int ind = chs.length - 1, pos = out.length - 1;
        while (ind >= 1) {
            out[pos--] = (byte) (hexCharToByte(chs[ind - 1])<<4 | hexCharToByte(chs[ind]));
            ind -= 2;
        }
        if (ind == 0) out[pos] = hexCharToByte(chs[ind]);
        return out;
    }

    /**
     * Translates a hex digit (in the form of an ASCII character)
     * to a byte
     */
    private static byte hexCharToByte(char c) {
        byte out;
        if (c >= 48 && c <= 59) out = (byte) (c - 48);
        else if (c >= 97 && c <= 102) out = (byte) (c - 87);
        else if (c >= 65 && c <= 70) out = (byte) (c - 55);
        else throw new IllegalArgumentException("Char " + c + " does not correspond to a hex digit.");

        return out;
    }
}
