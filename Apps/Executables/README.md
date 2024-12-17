# Passing arguments to the executables.
**Important**: Right now I am assuming you have a key available; if you do not, please run the encryption executable with no
arguments:
```
./AESencryption.exe
```
Then, the program will give you instructions for the creation of public-private key pairs (and other encryption options, if desired).
The following image shows the process creating and saving keys:

![Key Creation](../../Images/KeyCreation.gif)

We can pass arguments to the executables to encrypt/decrypt a single file. Set as first argument the name/path of the encryption
key we want to use followed by the files (currently supported) that are meant to be encrypted as the following arguments, this
will encrypt/decrypt the files using the key referenced in the first argument.

**Examples:**

Note: Videos were edited to decrease the size of these gifts.

1. Encrypting two ``bmp`` images by passing the relative paths of these files to the executable. In concrete, executing:
``./AESencryption.exe AESencryption.aeskey Files_for_testing/Pic00.bmp Files_for_testing/Pic01.bmp``.

![Encryption](../../Images/AESencryption.gif)

2. Decrypting two text files by passing the relative paths of these files to the executable. In concrete, executing:
``./AESdecryption.exe AESencryption.aeskey Files_for_testing/Text00.txt Files_for_testing/Text01.txt``.

![Decryption](../../Images/AESdecryption.gif)

