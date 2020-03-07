/*
 * Defines the cli arguments for KHash.
 * Author: Spencer Little
 */

package main.args;

import com.beust.jcommander.Parameter;

/**
 * Defines the cli arguments for KHash.
 * @author Spencer Little
 * @version 1.0.0
 */
public class HashArgs {

    @Parameter(names = { "-op", "-operation" }, description = "KMACKXOF256, cSHAKE256, SHA3.")
    public String op = "SHA3";

    @Parameter(names = { "-f", "-file" }, description = "Url to the file to be hashed.")
    public String inputUrl;

    @Parameter(names = { "-cs", "--customization-str" }, description = "The customization string for cSHAKE.")
    public String cString = "";

    @Parameter(names = { "-k", "-key" }, description = "Path to key file.")
    public String keyUrl;

    @Parameter(names = { "-w", "-write" }, description = "Write hash output to the provided URL.")
    public String outputUrl;

    @Parameter(names = { "-l", "-bitLen" }, description = "The desired output length, in bits.")
    public int bitLen = 512;

    @Parameter(names = { "-h", "-help" }, description = "Display help message")
    public boolean help = false;

    /*
     * Displays a help message specifying accepted and required cli arguments
     */
    public static void showHelp() {
        String help = "Options: \njava KHash " +
                "\n-op|-operation <KMACXOF256 or cSHAKE256 or SHA3> " +
                "\n-f|-file <file path or string> provide the data to be processed " +
                "\n-cs|--customization-str <an arbitrary string> the customization string for cSHAKE256 " +
                "\n-k|-key <URL corresponding to the key file> provides the key for KMACXOF256 " +
                "\n-l|--bit-length the desired length of the output in bits " +
                "\n-h|-help displays this help message" +
                "\n If no op, bitLen, or input mode is specified, default is SHA3-512.";
        System.out.println(help);
    }

}
