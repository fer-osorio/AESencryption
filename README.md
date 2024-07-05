# AES

AES implementation in C++.

An implementation of AES is developed to encrypt an array of bytes (char's) with a know length; then, it is used for the 
encryption of BMP images.

#   Compilation

Executing the command `make` in the command line will give you the two executable files `encrypt.exe` and `decrypt.exe`.
To obtain just `encrypt.exe`, type `make encrypt.exe`. Same with `decrypt.exe` file.

#   Usage

##  Executable Files
Supposing we are in the "Executable" directory, we can use the executable files in the following ways: 

### Input from command line interface (CLI).
Run the command `./encrypt` to encrypt to either input the names/paths of files you desire to encrypt or to create a new text 
file from the CLI. This action will not save the original text but a encrypted version of it. To decrypt the output file, just
run `./decrypt`; the .txt file name and the name of the file where the key is stored will be asked for the 
decryption, and the decrypted message will be shown in the CLI.

An example of encryption could be:

```
$ ./encrypt

Write the string you want to encrypt. To process the string sent the value 'EOF', which you can do by:

- Pressing twice the keys CTRL-Z for Windows.
- Pressing twice the keys CTRL-D for Unix and Linux.

This is a message with many dots.....................................................................................
```
Two files were written: `encryption.txt` that holds the encrypted message, and `encryption.key` that holds the necessary data for 
the decryption.

```
Encryption.txt content:

LtøÕºÀ;Õ{JÍÖÏ] mNy;(ùê©]šÈ]Zöv¿ÐõÂÇïõšÈ]Zöv¿ÐõÂÇïõšÈ]Zöv¿ÐõÂÇïõšÈ]Zöv¿ÐõÂÇïõšÈ]ZÇž«(rÃ¢~<ryšô
```
For the decryption:

```
$ ./decrypt

Decryption of .txt files.
Write the name of the .txt file you want to decrypt and then press enter: encryption.txt
Write the name of the .key file where the encryption key is saved: encryption.key
This is a message with many dots.....................................................................................�
```

### Passing arguments to the executable.
We can pass the name/path of the file (.bmp or .txt) you want to encrypt as an argument, this will encrypt your file and 
will write the used key in a binary file with a `.key` extension. If CBC mode was used then the initial vector (IV) will be 
written in the same `.key` file. For the decryption, execute `decrypt` and pass the name of the file containing the key (.key 
file) used in encryption as first argument and the name of the encrypted file (.bmp or .txt) as second argument.

**Example:**

Before executing `./encrypt Test01.bmp`.

![Before encryption](/EncryptionExample/BeforeEncryption.png)

The last action encrypts the image and writes the binary file `Test01.key`, this file contains the cryptographic key and (since
CBC mode was used) the initial vector. This image shows the moment before executing `./decrypt Test01.key Test01.bmp`.

![Before decryption](/EncryptionExample/BeforeDecryption.png)

Finally, the last command gives us the original image.

![After decryption](/EncryptionExample/AfterDecryption.png)

# Important notes:
* Right now the unique operation modes that are implemented are ECB (Electronic Code Book) and CBC (Cipher Block Chaining).
* The padding problem for the ECB and CBC mode is solved with a method not specified in the NIST standard.
* No attempt to generate secure cryptographic keys is made. 

