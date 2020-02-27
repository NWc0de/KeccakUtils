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

    @Parameter(names = { "--key-gen" }, description = "Generates a new EC key pair.")
    public boolean keyGen;

    @Parameter(names = { "-pub" }, description = "The url that the public key will be written to.")
    public String pubUrl;

    @Parameter(names = { "-prv" }, description = "The url that the private key will be written to.")
    public String prvUrl;

    @Parameter(names = { "-pwd" }, description = "The password used to generate the new EC key pair.")
    public String genPwd;

    @Parameter(names = { "--file-pwd" }, description = "The password under which the private key will be " +
            "encrypted before it is written to file.")
    public String filePwd = ""; // note: mention default encryption in readme
}
