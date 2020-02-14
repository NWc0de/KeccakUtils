/*
 * Implementation of the Keccak[c] function defined in NIST FIPS 202.
 * Author: Spencer Little
 * Date: 01/22/2020
 */

package sha3;

import java.util.Arrays;

/**
 * Implements the Keccak-p function and associated sponge modality.
 * @author Spencer Little
 */
public class Keccak {

    /* Round constants ref. https://keccak.team/keccak_specs_summary.html */
    private static final long[] rConst = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /*
     * Rotation offsets for the roh function.
     * ref. https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     */
    private static final int[] rotOffset = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /*
     * The position for each word with respective to the lane shifting in the pi function.
     * ref. https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     */
    private static final int[] piLane = {
            10, 7,  11, 17, 18, 3, 5, 16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    private enum ENCODE {Left, Right};

    /**
     * The Keccak Message Authentication with extensible output, ref NIST SP 800-185 sec 4.3.1
     * @param key the key
     * @param in the input bytes
     * @param bitLen the desired bit length
     * @param custStr the customization string
     * @return the message authentication code derived from the provided input
     */
    public static byte[] KMACXOF256(byte[] key, byte[] in, int bitLen, String custStr) {
        byte[] newIn = mergeByteArrays(bytepad(encodeString(key), 136), in);
        newIn = mergeByteArrays(newIn, lrEncode(0, ENCODE.Right));
        return cSHAKE256(newIn, bitLen,  "KMAC", custStr);
    }

    /**
     * cSHAKE func ref sec 3.3 NIST SP 800-185
     * @param in the byte array to hash
     * @param bitLen the bit length of the desired output
     * @param funcName the name of the function to use
     * @param custStr the customization string
     * @return the message digest based on Keccak[512]
     */
    public static byte[] cSHAKE256(byte[] in, int bitLen, String funcName, String custStr) {
        if (funcName.equals("") && custStr.equals("")) return SHAKE256(in, bitLen);

        byte[] fin = mergeByteArrays(encodeString(funcName.getBytes()), encodeString(custStr.getBytes()));
        fin = mergeByteArrays(bytepad(fin, 136), in);
        fin = mergeByteArrays(fin, new byte[] {0x04}); // append two zero bits here? from test vectors seems like 0x04 is convention

        return sponge(fin, bitLen, 512);
    }

    /**
     * Produces a variable length message digest based on the keccak-f perumation
     * over the user input. Ref. NIST FIPS 202 sec. 6.2
     * @param in the bytes to compute the digest of
     * @param bitLen the desired length of the output
     * @return the message digest extracted from the keccakp based sponge
     */
    public static byte[] SHAKE256(byte[] in, int bitLen) {
        byte[] uin = Arrays.copyOf(in, in.length + 1);
        uin[in.length] = 0x1f; // pad with suffix defined in FIPS 202 sec. 6.2
        return sponge(uin, bitLen, 512);
    }

    /**
     * The SHA-3 hash function defined in NIST FIPS 202.
     * @param in the bytes to compute the digest of
     * @param bitLen the desired length of the output (must be 224, 256, 384, or 512)
     * @return the message digest computed via the Keccak[bitLen*2] permutation
     */
    public static byte[] SHA3(byte[] in, int bitLen) {
        if (bitLen != 224 && bitLen != 256 && bitLen != 384 && bitLen != 512)
            throw new IllegalArgumentException("Supported output bit lengths are 224, 256, 384, and 512.");
        byte[] uin = Arrays.copyOf(in, in.length + 1);
        uin[in.length] = 0x06; // pad with suffix defined in FIPS 202 sec. 6.1
        return sponge(uin, bitLen, bitLen*2);
    }

    /**
     * The sponge function, produces an output of length bitLen based on the
     * keccakp permutation over in.
     * @param in the input byte array
     * @param bitLen the length of the desired output
     * @param cap the capacity see section 4 FIPS 202.
     * @return a byte array of bitLen bits produced by the keccakp permutations over the input
     */
    private static byte[] sponge(byte[] in, int bitLen, int cap) {
        int rate = 1600 - cap;
        byte[] padded = padTenOne(rate, in);
        long[][] states = byteArrayToStates(padded, cap);
        long[] stcml = new long[25];
        for (long[] st : states) {
            stcml = keccakp(xorStates(stcml, st), 1600, 24); // Keccak[c] restricted to bitLen 1600
        }

        long[] out = {};
        int offset = 0;
        do {
            out = Arrays.copyOf(out, offset + rate/64);
            System.arraycopy(stcml, 0, out, offset, rate/64);
            offset += rate/64;
            stcml = keccakp(stcml, 1600, 24);
        } while (out.length*64 < bitLen);

        return stateToByteArray(out, bitLen);
    }

    /**
     * Applies the 10*1 padding scheme, ref sec 5.1 FIPS 202, to a byte array. Assumes
     * padding required is byte wise (number of bits needed is multiple of 8).
     * @param in the bytes array to pad
     * @param rate the result will be a positive multiple of rate (in terms of bit length)
     * @return the padded byte array
     */
    private static byte[] padTenOne(int rate, byte[] in) {
        int bytesToPad = (rate / 8) - in.length % (rate / 8);
        byte[] padded = new byte[in.length + bytesToPad];
        for (int i = 0; i < in.length + bytesToPad; i++) {
            if (i < in.length) padded[i] = in[i];
            else if (i==in.length + bytesToPad - 1) padded[i] = (byte) 0x80; // does not append any domain prefixs
            else padded[i] = 0;
        }

        return padded;
    }


    /************************************************************
     *                    Keccak Machinery                      *
     ************************************************************/


    /**
     * The Keccack-p permutation, ref section 3.3 NIST FIPS 202.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the Keccak-p permutation has been applied
     */
    private static long[] keccakp(long[] stateIn, int bitLen, int rounds) {
        long[] stateOut = stateIn;
        int l = floorLog(bitLen/25);
        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++) {
            stateOut = iota(chi(rhoPhi(theta(stateOut))), i); // sec 3.3 FIPS 202
        }
        return stateOut;
    }

    /**
     * The theta function, ref section 3.2.1 NIST FIPS 202. xors each state bit
     * with the parities of two columns in the array.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the theta function has been applied (array of longs)
     */
    private static long[] theta(long[] stateIn) {
        long[] stateOut = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++) {
            C[i] = stateIn[i] ^ stateIn[i + 5] ^ stateIn[i + 10] ^ stateIn[i + 15] ^ stateIn[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            long d = C[(i+4) % 5] ^ lRotWord(C[(i+1) % 5], 1);

            for (int j = 0; j < 5; j++) {
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ d;
            }
        }

        return stateOut;
    }

    /**
     * The rho and phi function, ref section 3.2.2-3 NIST FIPS 202. Shifts and rearranges words.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after applying the rho and phi function
     */
    private static long[] rhoPhi(long[] stateIn) {
        long[] stateOut = new long[25];
        stateOut[0] = stateIn[0]; // first value needs to be copied
        long t = stateIn[1], temp;
        int ind;
        for (int i = 0; i < 24; i++) {
            ind = piLane[i];
            temp = stateIn[ind];
            stateOut[ind] = lRotWord(t, rotOffset[i]);
            t = temp;
        }
        return stateOut;
    }

    /**
     * The chi function, ref section 3.2.4 NIST FIPS 202. xors each word with
     * a function of two other words in their row.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after applying the chi function
     */
    private static long[] chi(long[] stateIn) {
        long[] stateOut = new long[25];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                long tmp = ~stateIn[(i+1) % 5 + 5*j] & stateIn[(i+2) % 5 + 5*j];
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ tmp;
            }
        }
        return stateOut;
    }

    /**
     * Applies the round constant to the word at stateIn[0].
     * ref. section 3.2.5 NIST FIPS 202.
     * @param stateIn the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after the round constant has been xored with the first lane (st[0])
     */
    private static long[] iota(long[] stateIn, int round) {
        stateIn[0] ^= rConst[round];
        return stateIn;
    }


    /************************************************************
     *                    Auxiliary Methods                     *
     ************************************************************/

    /**
     * Pads a bit string, sec 2.3.3 NIST SP 800-185
     * @param str the bit string to pad
     * @param w the desired factor of the padding
     * @return a byte array prepended by lrEncode(w) such that it's length is an even multiple of w
     */
    private static byte[] bytepad(byte[] str, int w) {
        byte[] lEnc = lrEncode(w, ENCODE.Left);
        int len = lEnc.length + str.length + (w - (lEnc.length + str.length) % w);
        byte[] out = Arrays.copyOf(lEnc, len);
        System.arraycopy(str, 0, out, lEnc.length, str.length);
        return out;
    }

    /**
     * The encodeString func, NIST SP 800-185 2.3.2
     * @param str the bit string to encode (as a byte array)
     * @return the bit string produced by prepending the encoding of str.length to str
     */
    private static byte[] encodeString(byte[] str) {
        byte[] lEnc = lrEncode(str.length*8, ENCODE.Left); // bitwise length encoding
        byte[] out = Arrays.copyOf(lEnc, lEnc.length + str.length);
        System.arraycopy(str, 0, out, lEnc.length, str.length);
        return out;
    }

    /**
     * The left/right encode func specified in sec. 2.3.1 NIST SP 800-185
     * @param len the integer to encode
     * @param dir the desired direction of the encoding
     * @return a byte array: see NIST SP 800-185 sec. 2.3.1
     */
    private static byte[] lrEncode(long len, ENCODE dir) {
        if (len==0) return dir == ENCODE.Left ? new byte[] {1, 0} : new byte[] {0, 1};
        byte[] buf = new byte[8];
        long l = len;
        int cnt = 0;
        while (l > 0) {
            byte b = (byte) (l & 0xffL);
            l = l>>>(8);
            buf[7 - cnt++] = b; // reverse for appropriate ordering
        }
        byte[] out = new byte[cnt + 1];
        System.arraycopy(buf, 8 - cnt, out, dir == ENCODE.Left ? 1 : 0, cnt);
        out[dir == ENCODE.Left ? 0 : out.length - 1] = (byte) cnt;
        return out;
    }

    /**
     * Converts an extended state array to an array of bytes of bit length bitLen (equivalent to Trunc_r).
     * @param state the state to convert to a byte array
     * @param bitLen the bit length of the desired output
     * @return a byte array of length bitLen/8 corresponding to bytes of the state: state[0:bitLen/8]
     */
    private static byte[] stateToByteArray(long[] state, int bitLen) {
        if (state.length*64 < bitLen) throw new IllegalArgumentException("State is of insufficient length to produced desired bit length.");
        byte[] out = new byte[bitLen/8];
        int wrdInd = 0;
        while (wrdInd*64 < bitLen) {
            long word = state[wrdInd++];
            int fill = wrdInd*64 > bitLen ? (bitLen - (wrdInd - 1) * 64) / 8 : 8;
            for (int b = 0; b < fill; b++) {
                byte ubt = (byte) (word>>>(8*b) & 0xFF);
                out[(wrdInd - 1)*8 + b] = ubt;
            }
        }

        return out;
    }

    /**
     * Converts a byte array to series of state arrays. Assumes input array is
     * evenly divisible by the rate (1600-cap)
     * @param in the input bytes
     * @param cap the capacity see section 4 FIPS 202.
     * @return a two dimensional array corresponding to an array of in.length/(1600-cap) state arrays
     */
    private static long[][] byteArrayToStates(byte[] in, int cap) {
        long[][] states = new long[(in.length*8)/(1600-cap)][25];
        int offset = 0;
        for (int i = 0; i < states.length; i++) {
            long[] state = new long[25];
            for (int j = 0; j < (1600-cap)/64; j++) {
                long word = bytesToWord(offset, in);
                state[j] = word;
                offset += 8;
            }
            // remaining (capacity/64) words will be 0, ref alg 8. step 6 FIPS 202
            states[i] = state;
        }
        return states;
    }

    /**
     * Converts the bytes from in[l,r] into a 64 bit word (long)
     * @param offset the position in the array to read the eight bytes from
     * @param in the byte array to read from
     * @return a long that is the result of concatenating the eight bytes beginning at offset
     */
    private static long bytesToWord(int offset, byte[] in) {
        if (in.length < offset+8) throw new IllegalArgumentException("Byte range unreachable, index out of range.");
        // does endianness matter here?
        long word = 0L;
        for (int i = 0; i < 8; i++) {
            word += (((long)in[offset + i]) & 0xff)<<(8*i);
        }
        return word;
    }

    private static byte[] mergeByteArrays(byte[] b1, byte[] b2) {
        byte[] mrg = Arrays.copyOf(b1, b1.length + b2.length);
        System.arraycopy(b2, 0, mrg, b1.length, b2.length);
        return mrg;
    }

    private static long[] xorStates(long[] s1, long[] s2) {
        long[] out = new long[25];
        for (int i = 0; i < s1.length; i++) {
            out[i] = s1[i] ^ s2[i];
        }
        return out;
    }

    private static long lRotWord(long w, int offset) {
        int ofs = offset % 64;
        return w << ofs | (w >>>(Long.SIZE - ofs));
    }

    private static int floorLog(int n) {
        if (n < 0) throw new IllegalArgumentException("Log is undefined for negative numbers.");
        int exp = -1;
        while (n > 0) {
            n = n>>>1;
            exp++;
        }
        return exp;
    }


}
