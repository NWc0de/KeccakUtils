/*
 * A utility object to enable passing data and a boolean indicating
 * it's validation status.
 */

package util;

/**
 * An object that encapsulates a byte array and a boolean
 * indicator of that data's validity.
 * @author Spencer Little
 * @version 1.0.0
 */
public class DecryptedData {
    /** Indicates whether the encapsulated byte array has been validated. */
    private boolean isValid;
    /** The byte array containing the data that was validated. */
    private byte[] data;

    /**
     * Constructs a DecryptedData object with the provided
     * validity and data.
     * @param isValid a boolean indicating whether the data has been validated
     * @param data a byte array containing the data
     */
    public DecryptedData(boolean isValid, byte[] data) {
        this.isValid = isValid;
        this.data = data;
    }

    /** Returns a flag indicating the data's validation status. */
    public boolean isValid() {return isValid;}
    /** Returns the data as a byte array. */
    public byte[] getBytes() {return data;}
}
