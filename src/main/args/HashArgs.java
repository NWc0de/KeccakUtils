/*
 * Defines the cli arguments for KHash.
 * Author: Spencer Little
 */

package main.args;

import com.beust.jcommander.Parameter;

/**
 * Defines the cli arguments for KHash.
 * @author Spencer Little
 */
public class HashArgs {

    @Parameter(names = { "-op", "-operation" }, description = "KMACKXOF256, cSHAKE256.", required = true)
    public String op;

    @Parameter(names = { "-im", "--input-mode" }, description = "Type of input provided, <file> or <string>", required = true)
    public String inputMode;

    @Parameter(names = { "-i", "-input" }, description = "Interpret the following string as file name or raw input (based on mode).", required = true)
    public String inputSource;

    @Parameter(names = { "-cstr", "--customization-str" }, description = "The customization string for cSHAKE.")
    public String cString = "";

    @Parameter(names = { "-k", "-key" }, description = "Path to key file.")
    public String keyFilePath;

    @Parameter(names = { "-w", "-write" }, description = "Write hash output to the provided URL.")
    public String outputFile;

    @Parameter(names = { "-l", "-bitLen" }, description = "The desired output length, in bits.")
    public int bitLen = 4096;

    @Parameter(names = { "-h", "-help" }, description = "Display help message")
    public boolean help = false;

    /*
     * Displays a help message specifying accepted and required cli arguments
     */
    public static void showHelp() {
        String help = "Options: \njava KHash \n-op|-operation <KMACXOF256 or cSHAKE256> " +
                "\n-im|--input-mode <file or string> file -> interpret as URL, string -> read bytes directly " +
                "\n-i|-input <file path or string> provide the data to be processed " +
                "\n-cstr|--customization-str <an arbitrary string> the customization string for cSHAKE256 " +
                "\n-k|-key <URL corresponding to the key file> provides the key for KMACXOF256 " +
                "\n-h|-help displays this help message";
        System.out.println(help);
    }

}
