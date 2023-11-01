# AES

AES implementation in C++.

An implementation of AES is developed to encrypt an array of bytes (char's) with a know length; then, it is used for the 
encryption of BMP images.

#   Usage

##  Executables
Supousing we are in the "Executable" directory, we can use the executables un the following ways

### Input from command line interface (CLI).
Run the commnad `./encrypt` to encrypt text from the CLI. This action wil create a .txt file with the encrypted text. To decrypt
the output file, just run `./decrypt`; the .txt file name and the name of the file where the key is stored will be asked for the 
decryption, and the decrypted message will be shown in the CLI.

An example of encryption could be

```
$ ./encrypt

Write the string you want to encrypt. To process the string sent the value 'EOF', which you can do by:

- Pressing twice the keys CTRL-Z for Windows.
- Pressing twice the keys CTRL-D for Unix and Linux.

This is a message with many dots.....................................................................................
```
Two files were written: `encryption.txt` that holds the encrypted message, and `encryption.key` that holds the necesary data for 
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

### BMP images.
Execute the file `encrypt` and pass the name of the image you want to encrypt as an argument, for example `./encrypt Test00.bmp`. 
This will encrypt your image and will write the used key in a binary file with a `.key` extension. If CBC mode was used (witch it 
will since is the unique one avaible now), then the initial vector (IV) will be writed in the same file.

For the decryption, execute pass the name of the file containing the key (.key file) as first argument and the name of the BMP 
image as second argument, for example `./decryp Test00.key Test00.bmp`.

# Important notes:
* Right now the unique operation modes that are implemented are ECB (Electronic Code Book) and CBC (Cipher Block Chaining).
* The padding problem for the ECB and CBC mode is solved with a method not specified in the NIST standard.
* No attempt to generate secure cryptographic keys is made. 
