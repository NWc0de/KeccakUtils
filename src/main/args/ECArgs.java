/*
 * Defines the cli arguments for the ECUtil services.
 */

package main.args;

import com.beust.jcommander.Parameter;

/**
 * Defines the cli args for the ECUtil services.
 * @author Spencer Little
 * @version 1.0.0
 */
public class ECArgs {

    @Parameter(names = { "-op", "-operation" }, description = "Specify the operation, <keygen, encrypt, decrypt, sign, verify>")
    public String op;

    @Parameter(names = { "-pwd" }, description = "The password used to generate the EC key pair used for the specified operation.")
    public String genPwd;

    @Parameter(names = { "-pub" }, description = "The URL corresponding the public key file to be used for the specified operation.")
    public String pubUrl;

    @Parameter(names = { "-prv" }, description = "The URL corresponding the private key file to be used for the specified operation.")
    public String prvUrl;

    @Parameter(names = { "-rpwd" }, description = "The password under which the private key is encrypted ")
    public String prvPwd;

    @Parameter(names = { "-f", "--file-name" }, description = "The source of the data to be processed.")
    public String dataUrl;

    @Parameter(names = { "-s", "-signature" }, description = "The url of the file containing the signature to the be considered during validation")
    public String sigUrl;

    @Parameter(names = { "-o", "--output-url" }, description = "The url for the processed data to be written to.")
    public String outUrl;

    @Parameter(names = { "-h", "-help" }, description = "Display help message.")
    public boolean help = false;

    /*
     * Displays a help message specifying accepted and required cli arguments
     */
    public static void showHelp() {
        String help = "Options: \njava ECUtils " +
                "\n-op|-operation <keygen, encrypt, decrypt, sign, verify> " +
                "\n-pwd the password used to generate the EC key pair used for the specified operation " +
                "\n-pub the url corresponding to the public key file to use for the specified operation " +
                "\n-prv the url corresponding to the private key file to use for the specified operation " +
                "\n-rpwd the password under which the private key is encrypted " +
                "\n-f|--file-name the url corresponding to the source of the data to be processed " +
                "\n-o|--output-url the url corresponding to which the output data will be written " +
                "\n-s|-signature the url of the file containing the signature to be considered during validation " +
                "\n-h|-help displays this help message" +
                "\n If no file password is specified during key generation the private key file is encrypted " +
                "under the password used to generate the key.";
        System.out.println(help);
    }
}
