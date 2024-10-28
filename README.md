#  AES

AES (Advance Encryption Standard) implementation in C++, applied to the encryption of BMP images and text files.

Mail me at aosorios1502@alumno.ipn.mx and alexis.fernando.osorio.sarabio@gmail.com for questions and comments.

#  Overview

Implementation of symmetric block cipher AES (published by [NIST](https://www.nist.gov/)) in a name space called AES. Specification of this standard can be found [here](https://www.nist.gov/publications/advanced-encryption-standard-aes-0). Then, AES class, together with other structures, is used to encrypt Text files and BMP images.

At the moment of writing this README, the supported operation modes are:

- ECB [Electronic Code Book]
- CBC [Cipher Block Chaining]
- PVS [Pi and Variable Sbox] (Experimental, not specified in the standard)

And all key length specified in the standard (that is: 128, 192 and 256 bits) are supported. Also, the supported files are

- Text files (.txt)
- Bitmap images (.bmp)

**Important note**: AES name space does not implement any method to obtain secure cryptographic keys.

#   Usage

##  Creating a Cipher object
Before encrypting anything, we need to establish a cryptographic key length, a cryptographic key and a operation mode. All this objects are specified inside a structure called **Key** inside the same name space **AES**. A **Key** object can be created by

1. Using ``Key(const char* const _key, Length, OperationMode, const char* const _IV = NULL);``. This establish all attributes manually. The ``_IV`` argument stands for "Initial Vector"; is intended for CBC mode.
2. Using ``Key(const char*const fname)``. This builds the key from a binary file.

This structure is necessary to create a Cipher object because the unique constructor it has (apart from default constructor and copy constructor) is ``Cipher(const Key&)``. The intention of this is to have a well constructed cryptographic key before use it to encrypt.

***In summary, to create a Cipher object:***
1. Create a **Key** object, either manually or from a file.
2. Use the constructor ``Cipher(const Key&)``.

**Important note**: The default constructor for Cipher, ``Chipher()``, sets each byte of key and key expansion as zero, so is mandatory to not use this constructor for an actual encryption application.

## Encryption and decryption

Once we have a Cipher object, for encryption it is only necessary to invoke the member function 

```
void encrypt(char*const data, unsigned size)const
```

Same for encryption

```
void decrypt(char*const data, unsigned size)const
```

Encryption and decryption process will succeed if and only if the Cipher objects used in each end have the same key.

***Important note***: Each of the two functions above will act on the bytes pointed by **data** without creating a copy of the original content.

### Encrypting and decrypting files.

To this end, ``encrypt`` and ``decrypt`` functions are overloaded so they can accept a file structure and a Cipher object as arguments. In higher detail,

```
friend void encrypt(Bitmap& bmp, AES::Cipher& e)
```

encrypts ``bmp`` Bitmap file using the Cipher object ``e``. Notice this last function is a friend of class ``Bitmap``, this has two intentions: First, to be capable to encrypt the bmp file data while maintaining its attributes private, and second, to have the possibility of encrypt several files with one single Cipher file.

Similarly, function
```
friend void decrypt(Bitmap& bmp, AES::Cipher& e)
```
decrypts ``bmp`` Bitmap file using Cipher object ``e``.

The same is true for the rest of the files supported.

```
friend void encrypt(TXT& txt, AES::Cipher& e)
```

```
friend void decrypt(TXT& txt, AES::Cipher& e)
```

#  Executable Files

##  Compilation

Executing the command `make` in the command line will give you the two executable files `encrypt.exe` and `decrypt.exe`.
To obtain just `encrypt.exe`, type `make encrypt.exe`. Same with `decrypt.exe` file.

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

![Before encryption](/Examples/BeforeEncryption.png)

The last action encrypts the image and writes the binary file `Test01.key`, this file contains the cryptographic key and (since
CBC mode was used) the initial vector. This image shows the moment before executing `./decrypt Test01.key Test01.bmp`.

![Before decryption](/Examples/BeforeDecryption.png)

Finally, the last command gives us the original image.

![After decryption](/Examples/AfterDecryption.png)

# Important notes:
* Right now the unique operation modes that are implemented are ECB (Electronic Code Book) and CBC (Cipher Block Chaining).
* The padding problem for the ECB and CBC mode is solved with a method not specified in the NIST standard.
* No attempt to generate secure cryptographic keys is made. 

