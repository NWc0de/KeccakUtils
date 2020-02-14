# KeccakUtils

The following library provides a range of cryptographic functions (KMACXOF256, SHAKE256, cSHAKE256) as well as several cli utilities built on top of them (hash computation, symmetric encryption). This Keccak implementation is NIST compliant (ref. [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)), see the unit tests ```KeccakTest.java``` for more details. 

## Keccak
The core Keccak functions are implemented in Keccak.java (along with the associated sponge modality). SHAKE256, cSHAKE256, and KMACXOF256 are all made available through this class. The associated set of unit tests, TestKeccak.java, demonstrates compliance with the NIST standard, [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).

#### KHash
The Khash cli utility enables access to SHA3 (224, 256, 384, 512), cSHAKE256 (and consequently SHAKE256), and KMACXOF256 directly from the command line.

To compute the SHA3 hash of a file:

```aidl
java KHASH -im file -i test.txt
```

SHA3 is the default operation so no 'op' parameter is necessary. The default bit length is 512 bits, but different bit lengths can be specified with the 'l' parameter (input is interpreted as **bit** length but must be a multiple of 8). The command above will compute the SHA3-512 hash of test.txt and display the result to the command line. An equivalent, and explicit, version of the command above is:

```aidl
java KHASH -op SHA3 -im file -i test.txt -l 512
```

To compute the hash of a file with cSHAKE256:
```aidl
java KHash -op cSHAKE256 -im file -i test.txt 
```
Running the line above will compute the hash of the provided file and display the result to the command line. The 'cs' parameter allows a customization string to be defined (see NIST SP 800-185 for more details). The default customization string is an empty string, which renders cSHAKE256 equivalent to SHAKE256.

To compute the hash of a raw string:
```aidl
java KHash -op cSHAKE256 -im string -i test
``` 

Alternatively, KMACXOF256 is available as a keyed hash function. 

To compute the hash of a file with KMACXOF256:
```aidl
java KHASH -op KMACXOF256 -im file -i test.txt -k keyfile 
```

To compute the hash of a raw string with KMACXOF256:
```aidl
java KHASH -op KMACXOF256 -im string -i test -k keyfile
```

A key is required for KMACXOF256. 

In either mode output may be saved to a file with the -w flag. 

## KCipher
KCipher is a cli utility that provides authenticated symmetric encryption services based on the Keccak machinery (KMACXOF256). Encryption is performed under a user provided password. 

To encrypt a file under the password, 'pass':
```aidl
java KCipher -e -f private.txt -pws pass -o enc.txt 
```

The command above will encrypt ```private.txt``` under the password, 'pass', and write the output to ```enc.txt```. It is also possible to provide the password as a file:

```aidl
java KCipher -e -f private.txt -pwf pswd.txt -o enc.txt
```

Decrypting a file under a given password can be accomplished in a similar fashion:
```aidl
java KCipher -d -f enc.txt -pwf pswd.txt -o dec.txt
```

The key may be passed as a string during decryption as well:
```aidl
java KCipher -d -f enc.txt -pws pass -o dec.txt
```

The authentication tag (automatically computed during encryption) is checked by default. If the tags do not match no data is written and a warning is presented. This behavior can be disabled with the -i tag, however this is not advisable. If authentication is disabled, the user will still be informed as to whether the computed authentication tag matches the one in the file provided, but no action will be taken. 
