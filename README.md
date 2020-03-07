# KeccakUtils

KeccakUtils provides a range of cryptographic functions: SHA3/cSHAKE256 hash computation, authenticated encryption via KMACXOF256, elliptic curve key generation, asymmetric encryption (ECDHIES), and Schnorr signature generation and validation. The elliptic curve that provides the basis for the ECDHIES and Schnorr signature utilities is an Edwards curve (ed5211). The Keccak primitives are NIST compliant. Compliance testing was done in the style of NIST's Cryptographic Algorithm Validation Program using the suite of test vectors available on the [NIST CAVP page](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing).

The core Keccak functions are implemented in ```Keccak.java``` (along with the associated sponge modality). SHA3, SHAKE256, cSHAKE256, and KMACXOF256 are made available through this class. The associated set of unit tests, ```SHA3Test.java``` and ```SHAKETest.java```, demonstrate compliance with NIST standards [NIST FIP 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) and [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf).

## KHash
The Khash cli utility enables access to SHA3 (224, 256, 384, 512), cSHAKE256, and KMACXOF256 directly from the command line.

To compute the SHA3 hash of a file:

```aidl
java KHASH -f test.txt
```
The command above will compute the SHA3-512 hash of ```test.txt``` and display the output to the console. In the absence of an 'op' parameter SHA3 is implied. Variable output lengths can be specified with the 'l' parameter (interpreted as bit length), although SHA3 output bit lengths are restricted to 224, 256, 384, 512. The command above is equivalent to:

```aidl
java KHASH -op SHA3 -f test.txt -l 512
```

In the absence of a file parameter, 'f', the option to provide input directly to the console is provided. 

To compute the hash of the raw string 'test':
```aidl
java KHash  
---------------------------------------------------
Enter message to be hashed:

test
More text? y/n
n
SHA3 512 bits (Console input): 
9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14
``` 
This option is available with cSHAKE256 and KMACXOF256 as well.

To compute the hash of a file with cSHAKE256:
```aidl
java KHash -op cSHAKE256 -f test.txt 
```
Executing KHash with the cSHAKE256 parameter will compute the cSHAKE256 hash of the provided input and display the digest to the command line. The 'cs' parameter allows a customization string to be defined (see [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf) for more details). By default the customization string is an empty string, which renders cSHAKE256 equivalent to SHAKE256.

To compute the cSHAKE256 hash of ```test.txt``` under customization string 'test':
```aidl
java KHash -op cSHAKE256 -cs test -f test.txt 
```

Alternatively, KMACXOF256 is available as a keyed hash function. 

To compute the KMACXOF256 hash of ```test.txt``` under the key bytes provided by ```keyfile```:
```aidl
java KHASH -op KMACXOF256 -f test.txt -k keyfile 
```

In all modes output may be saved to a file with the -w flag. 

To write the SHA3-512 hash of ```test.txt``` to url ```hashbytes```:
```aidl
java KHASH -f test.txt -k keyfile -w hashbytes
```

## KCipher
KCipher is a cli utility that provides authenticated symmetric encryption services derived from the KMACXOF256 primitive. The user provided password is combined with some psuedo-random bytes from ```SecureRandom``` and the resulting byte array is passed to KMACXOF256 as a key to generate two auxiliary keys. Both keys are again used with KMACXOF256, one to produce a mask that will be xored with the message to produce the ciphertext, and the other to compute the message authentication code. 

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
java KCipher -d -f enc.txt -pwd pass -o dec.txt
```
It is also possible to provide a password file for decryption:
```aidl
java KCipher -d -f enc.txt -pwf pswd.txt -o dec.txt
```

The authentication tag (automatically computed during encryption) is checked by default. If the tags do not match no data is written to disk and a warning is presented. This behavior can be disabled with the 'i' flag, however this is not recommended. If authentication is disabled, the user is still informed of the validity of the authentication tag but the decrypted data will be written to disk regardless of the validity of the MAC.

## ECUtils
ECUtils is a cli utility that provides a range of asymmetric crypto services provided by elliptic curve based protocols over the Edwards curve ed5211. For more information about this specific curve and the associated arithmetic algorithms see ```CurvePoint.java```. This utility package enables the user to generate key pairs, encrypt and store key pairs (encryption of private key files is done with the ```KCipher``` method described above), and encrypt/decrypt and sign messages with the generated elliptic curve key pairs.  

### Key Generation

Key generation is done by using KMACXOF256, in conjunction with a user provided password, to derive the private key (```s```, a ```BigInteger```), which is then multiplied with the public constant point ```G``` to generate the public key (```V```, a ```CurvePoint```), to create a public key pair ```(s, V)```. For more details about this process see ```ECKeyPair.java```. 

To generate a new keypair under the password 'test' and write the public key to url ```pub``` and the private key to url ```prv```:
```aidl
java ECUtils -op keygen -pub pub -prv prv -pwd test
---------------------------------------------------
New EC key pair successfully generated.
Private key encrypted under password test and written to url: prv
Public key written to url: pub
```
By default the private key is encrypted under the password used to generate the key pair. A seperate password for encrypting the private key file can be specified with the 'rpwd' parameter. 

To generate a new keypair under the password 'test' and write the public key to url ```pub``` and the private key to url ```prv``` (encrypted under password 'pftest'):
```aidl
java ECUtils -op keygen -pub pub -prv prv -pwd test -rpwd pftest
```
Public and private keys are serialized based on a straightforward algorithm that can be found in ```CurvePoint``` and ```ECKeyPair```. 

### Encryption
Encryption is done by generating a large random integer, ```k```, with ```SecureRandom``` then, give a public key ,```V```, two points are computed ```W = k*V``` and ```Z = k*G```. ```W``` is then passed to KMACXOF256 as a key and used to generate the two auxiliary keys described above in ```KCipher```. The encryption algorithm then proceeds as it does in ```KCipher```, except that ```Z``` is transmitted along with the ciphertext and the MAC. 

During decryption ```W``` is recomputed from ```Z``` using the private key, ```s```, ```W = s*Z```. Note the because ```V = s*G``` and ```Z = k*G```, ```s*Z = s*k*G = k*V = W```. W is again used to recompute two auxiliary keys and the decryption algorithm follows the same protocol as ```KCipher```.

To encrypt ```test.txt``` under a given public key, ```pub```, and write the encrypted file to ```enc.txt```:
```aidl
java ECUtils -op encrypt -pub pub -f test.txt -o enc.txt
```
During decryption the private key can either be passed as a file or generated from a password.

To decrypt ```enc.txt``` under the password 'test' and write the decrypted data to ```dec.txt```:
```aidl
java ECUtils -op decrypt -pwd test -f enc.txt -o dec.txt
```
To perform the same operation except using the private key file ```prv``` (encrypted under password 'pftest') to derive the private key:
```aidl
java ECUtils -op decrypt -prv prv -rpwd pftest -f enc.txt -o dec.txt
```

### Signatures
ECutils uses the Schnorr signature scheme to compute and verify signatures. This involves generating a large random ```k``` with a user provided password and KMACXOF256, which is then multiplied by the public constant point ```G``` to generate, ```U = k*G```. Instead of a challenge response protocol, the scheme employed by ECUtils more closely resembles a SNARK. ```U``` is used in conjunction with KMACXOF256 and the message to be signed to generate a large integer ```h``` which is one half of the signature along with ```z = (k - h*s) mod r```, where ```s``` is the private scalar of the key that is signing the message and ```r``` is a constant related to ed5211 (see ```CurvePoint.java``` for details). 

The signature, ```(h, z)```, can then be verified with the corresponding public key, ```V```, by computing ```U = z*G + h*V```, and then using ```U``` with KMACXOF256 and the message that was signed to recompute ```h```, and checking whether the computed ```h``` matches the ```h``` in the signature. Note that because ```z = (k - h*s) mod r```, ```z*G = k*G - h*s*G```, and because ```V = s*G```, recomputing ```U``` with ```(h, z)``` results in ```k*G - h*s*G + h*s*G = k*G = U```. More details about this protocol can be found in the ```ECSign.java``` class.

To sign ```test.txt``` under the private key generated by the password 'test' and write the signature to url ```sgn```:
```aidl
java ECUtils -op sign -pwd test -f test.txt -o sgn
``` 

To sign ```test.txt``` under the private key file ```prv``` (encrypted under password 'pftest') and write the signature to url ```sgn```:
```aidl
java ECUtils -op sign -prv prv -rpwd pftest -f test.txt -o sgn
```

To verify a signature, ```sgn```, of ```test.txt``` with the public key file ```pub```:
```aidl
java ECUtils -op verify -f test.txt -s sgn -pub pub
```

Signatures are serialized and parsed with a straightforward algorithm that can be found in ```ECSign.java```.