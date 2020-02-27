/*
 * Defines the cli arguments for KCipher.
 * Author: Spencer Little
 */

package main.args;

import com.beust.jcommander.Parameter;

/**
 * Defines the cli args for the KCipher.
 * @author Spencer Little
 * @version 1.0.0
 */
public class CipherArgs {

    @Parameter(names = { "-e", "-encrypt" }, description = "Encrypt the provided data.")
    public boolean encrypt;

    @Parameter(names = { "-d", "-decrypt" }, description = "Decrypt the provided data.")
    public boolean decrypt;

    @Parameter(names = { "-f", "-file" }, description = "Provide the path to file to be encrypted.", required = true)
    public String inputURL;

    @Parameter(names = { "-i", "--ignore-checksum" }, description = "Write data to file even if the checksum does not match.")
    public boolean ignoreTag = false;

    @Parameter(names = { "-pws", "--password-str" }, description = "Provide the password as a String.")
    public String pwdStr;

    @Parameter(names = { "-pwf", "--password-file" }, description = "Provide the password as a URL.")
    public String pwdFile;

    @Parameter(names = { "-o", "-output" }, description = "Write output to the provided URL.", required = true)
    public String outputURL;

    @Parameter(names = { "-h", "-help" }, description = "Display help message")
    public boolean help = false;

    /*
     * Displays a help message specifying accepted and required cli arguments
     */
    public static void showHelp() {
        String help = "Options: \njava KCipher " +
                "\n-e|-encrypt encrypt the provided data " +
                "\n-d|-decrypt decrypt the provided data " +
                "\n-f|-file the url to the file to be encrypted " +
                "\n-i|--ignore-checksum write data to file even if the computed checksum does not match the checksum transmitted " +
                "\n-pws|--password-str provide the password directly to stdin as a string " +
                "\n-pwf|--password-file provide the password as a URL " +
                "\n-o|-output write the output to the provided URL " +
                "\n-h|-help displays this help message";
        System.out.println(help);
    }
}
