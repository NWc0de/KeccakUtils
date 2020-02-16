# KeccakUtils

KeccakUtils provides a range of cryptographic functions (SHA3/cSHAKE256 hash computation, symmetric encryption via KMACXOF256 duplexed sponge, and ECDHIES key generation and signing) built on top of a rigorously tested NIST compliant Keccak implementation. Compliance testing was done in the style of NIST's Cryptographic Algorithm Validation Program using the suite of test vectors available on the [NIST CAVP page](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing).

## Keccak
The core Keccak functions are implemented in ```Keccak.java``` (along with the associated sponge modality). SHA3, SHAKE256, cSHAKE256, and KMACXOF256 are made available through this class. The associated set of unit tests, ```SHA3Test.java``` and ```SHAKETest.java```, demonstrate compliance with NIST standards [NIST FIP 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).

#### KHash
The Khash cli utility enables access to SHA3 (224, 256, 384, 512), cSHAKE256, and KMACXOF256 directly from the command line.

To compute the SHA3 hash of a file:

```aidl
java KHASH -im file -i test.txt
```
The command above will compute the SHA3-512 hash of ```test.txt``` and display the output to the console. In the absence of an 'op' parameter SHA3 is implied. Variable output lengths can be specified with the 'l' parameter (interpreted as bit length), although with SHA3 output bit lengths are restricted to 224, 256, 384, 512. The command above is equivalent to:

```aidl
java KHASH -op SHA3 -im file -i test.txt -l 512
```

To compute the hash of a file with cSHAKE256:
```aidl
java KHash -op cSHAKE256 -im file -i test.txt 
```
Executing KHash with the cSHAKE256 parameter will compute the cSHAKE256 hash of the provided input and display the digest to the command line. The 'cs' parameter allows a customization string to be defined (see [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf) for more details). By default the customization string is an empty string, which renders cSHAKE256 equivalent to SHAKE256.

To compute the hash of ```test.txt``` under customization string 'test':
```aidl
java KHash -op cSHAKE256 -cs test -im file -i test.txt 
```

There are two available input modes, both of which are specified with the 'im' flag. The 'file' input mode interprets the input, denoted by the 'i' parameter, as a url while the 'string' input mode interprets input as raw data (the text following the 'i' parameter is translated directory to bytes). 

To compute the hash of the raw string 'test':
```aidl
java KHash -op cSHAKE256 -im string -i test
``` 

Alternatively, KMACXOF256 is available as a keyed hash function. 

To compute the KMACXOF256 hash of ```test.txt``` under the key bytes provided by ```keyfile```:
```aidl
java KHASH -op KMACXOF256 -im file -i test.txt -k keyfile 
```

In all modes output may be saved to a file with the -w flag. 

To write the SHA3-512 hash of ```test.txt``` to ```hashbytes```:
```aidl
java KHASH -w hashbytes -im file -i test.txt -k keyfile
```

## KCipher
KCipher is a cli utility that provides authenticated symmetric encryption services via a duplexed KMACXOF256 sponge. Encryption is performed under a user provided password. 

To encrypt a file under the password, 'pass':
```aidl
java KCipher -e -f private.txt -pws pass -o enc.txt 
```

The command above will encrypt ```private.txt``` under the password, 'pass', and write the output to ```enc.txt```. The 'pws' (password string) option will interpret the text following the 'pws' parameter as the password by converting the ASCII text directly to bytes (see ```KCipher.java``` for details). It is also possible to provide the password as a file:

```aidl
java KCipher -e -f private.txt -pwf pswd.txt -o enc.txt
```
With the 'pwf' option password bytes are read directly from the specified file. 

Decrypting a file under a given password can be accomplished in a similar fashion:
```aidl
java KCipher -d -f enc.txt -pwf pswd.txt -o dec.txt
```

The authentication tag (automatically computed during encryption) is checked by default. If the tags do not match no data is written to disk and a warning is presented. This behavior can be disabled with the -i tag, however this is not recommended. If authentication is disabled, the user is still informed of the validity of the authentication tag but the decrypted data will be written to disk regardless of the validity of the MAC.
