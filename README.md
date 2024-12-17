#  AES

AES (Advance Encryption Standard) implementation in C++, applied to the encryption of BMP images and text files.

Mail me at aosorios1502@alumno.ipn.mx and alexis.fernando.osorio.sarabio@gmail.com for questions and comments.

#  Overview

Implementation of symmetric block cipher AES (published by [NIST](https://www.nist.gov/)) in a name space called AES. Specification
of this standard can be found [here](https://www.nist.gov/publications/advanced-encryption-standard-aes-0). Then, AES class,
together with other structures, is used to encrypt Text files and BMP images.

At the moment (21 of November, 2024), the supported operation modes are:

- ECB [Electronic Code Book]
- CBC [Cipher Block Chaining]
- PVS [Pi Variable Sbox] (experimental, not specified in the NIST standard)

And all key length specified in the standard (that is: 128, 192 and 256 bits) are supported. Also, the supported files are

- Text files (.txt)
- Bitmap images (.bmp)

## Important notes:
* AES name space does not implement any method to obtain secure cryptographic keys.
* Padding problem for the ECB and CBC mode is solved with a method not specified in the NIST standard.

#   Usage

##  Creating a Cipher object
Before encrypting anything, we need to establish a cryptographic key length, a cryptographic key and a operation mode. All this
objects are specified inside a structure called **Key** inside the same name space **AES**. A **Key** object can be created by

1. Using ``Key(const char* const _key, Length, OperationMode);``. This establish all attributes manually.
2. Using ``Key(const char*const fname)``. This builds the key from a binary file.

### The binary file for Key structure.
As you can notice in [AES.hpp](Source/AES.hpp), ``Key`` structure posses ``void save(const char* const fname)const; `` function, 
this function saves the relevant information carried by the ``Key`` object that invoked it. The structure of the resultingbinary
file is:

1. The first 6 bytes correspondes to the characters 'A''E''S''K''E''Y'.
2. The following 3 (bytes 7, 8, 9) characters corresponds to the operation mode.
3. The next 2 (bytes 10, 11) bytes represent the length of the key in bits.
4. Denoting the length of the key in bytes as lengthBytes, from the byte 11 to the byte lengthBytes+11 is written the actual key.
5. If the operation mode is "CBC", then the next 16 bytes (bytes lengthBytes+11 to lengthBytes+27) represent the initial vector.

The ``Key`` structure is necessary to create a Cipher object because the unique constructor it has (apart from default constructor
and copy constructor) is ``Cipher(const Key&)``. The intention of this is to have a well constructed cryptographic key before use it
to encrypt.

### In summary, to create a Cipher object:
1. Create a ``Key`` object, either manually or from a file.
2. Use the constructor ``Cipher(const Key&)``.

**Important note**: The default constructor for Cipher, ``Chipher()``, sets each byte of key and key expansion as zero, so is
mandatory to not use this constructor for nothing more than type declaration.

## Encryption and decryption

Once we have a Cipher object, for encryption of an array named ```data``` with ``size`` bytes it is only necessary to invoke the
member function 

```
void encrypt(char*const data, unsigned size)const
```

Same for decryption

```
void decrypt(char*const data, unsigned size)const
```

Encryption and decryption process will succeed if and only if the Cipher objects used in each end have the same key.

***Important note***: Each of the two functions above will act on the bytes pointed by **data** without creating a copy of the
original content.

### Encrypting and decrypting files.

To this end, ``File`` name space has ``encrypt`` and ``decrypt`` functions; they can accept a file structure and a Cipher object
as arguments. In higher detail,

```
friend void encrypt(Bitmap& bmp, AES::Cipher& e)
```

encrypts ``bmp`` Bitmap file using the Cipher object ``e``. Notice this last function is a friend of class ``Bitmap``, this has
two intentions: First, to be capable to encrypt the bmp file data while maintaining its attributes private, and second, to have
the possibility of encrypt several files with one single Cipher object.

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

# PVS operation mode

This is an experimental operation mode. It uses the digits of the number pi together with the key to generate a round key with size
equal to the size of the data to encrypt and a dynamic Sbox. To describe the algorithm, we will need some notation.

- ``piRoundkey``:   Round key mentioned above
- ``dinSubBytes``:  Similar to SubBytes function specified in NIST standard, but using the dynamic Sbox mentioned above.
- ``data``:         Data byte array
- ``size``:         Data size
- ``BLOCK_SIZE``:   Size of blocks specified in NIST standard, its value is 16

I will borrow some notation from C programming language; when doubts arise in the meaning of some particular section of code,
suppose it has the same meaning as if it were a peace of code in C. The algorithm for PVS operation mode for encryption is:

```
// Pseudo code for encryption with PVS mode
encryptPVS(data, size) {
    for(i = 0; i < size; i++)   data[i] ^= this->piRoundkey[i];
    for(i = 0; i < size; i+= BLOCK_SIZE) dinSubBytes(&data[i]);
    encryptECB(data, size);
}
```

Were ``encryptECB`` corresponds to AES encryption under ECB operation mode. Notice how we are supposing that ``size`` is a multiple of
``BLOCK_SIZE``, in a real implementation we have to attend this case.
The algorithm for decryption is very similar, as you can notice:

- ``dinSubBytesInv``:   Corresponds with the inverse function of ``dinSubBytes``.

```
// Pseudo code for decryption with PVS mode
decryptPVS(data, size) {
    decryptECB(data, size);
    for(i = 0; i < size; i+= BLOCK_SIZE) ``dinSubBytesInv``(&data[i]);
    for(i = 0; i < size; i++)   data[i] ^= this->piRoundkey[i];
}
```

It can be said that what decryption does is to apply the inverses of process in encryption in reveres order.

To create the functions ``dinSubBytes`` adn dinSubBytesInv, it is enough to calculate the arrays ``dinSbox`` ans its inverse dinSboxInv, The algorithm for the creation of
the arrays ``piRoundkey``, ``dinSbox`` and dinSboxInv is the following:

- ``SBOX_SIZE``:    Size of Sbox, fixed to 256
- ``dinSbox``:      Array of 256 elements representing the dynamic Sbox
- ``key``:          Cryptographic key
- ``pi``:           array containing the digits of the number pi, this array has the same size than ``data``
- ``NUM_SIZE``:     Size in bytes of the numbers we will be handling, fixed to 32 (equivalent to 256 bits)
- ``prkSize``:      Round key size, initialized as 0.
- ``size``:         Size desired for ``piRoundkey`` array
- ``a``,``b``:      Two 256 bits (32 bytes) unsigned numbers
- ``c``:            A 512 bits (64 bytes) unsigned number
- ``unWSBoxSz``:    Unwritten SBox size, amount of entries not defined yet. Initialized as ``SBOX_SIZE``
- ``buffer``:       Array that will be used in the creation of new Sbox
- ``uNum256bit``:   Funtion: takes an 256 bits array and interprets it as a 256 bits number

```
// Pseudo code for creation of PiRoundkey and dinamic Sbox with inverse
setPiRoundKeyAndDinSbox(key, size) {
    a = uNum256bit(key), b = 0, c = 0;
    prkSize = 0;
    unWSBoxSz = SBOX_SIZE;
    for(i = 0; prkSize < size; i += NUM_SIZE) {                                 // -Beginning with the creation of piRoundkey array
        b = uNum256bit(&pi[i]);                                                 // -Basically, take a chunck of 256 bits from pi array and treat it as a number
        c = a*b;                                                                // -Product with the number created from key
        for(j = 0 ; j < 2*NUM_SIZE; j++)                                        // -Writing the result on piRoundkey array. Remember, the product of two 256 bits
            piRoundkey[prkSize++] = c[j];                                       //  (32 bytes) numbers results on a 512 bits (64 bytes) number
    }
    for(i = 0; i < SBOX_SIZE; i++) buffer[i] = i;                               // -Filling buffer with 1, 2, ..., 255
        for(i = size-1, j = 0; unWSBoxSz > 0; i--, j++, unWSBoxSz--) {          // -Creating dinamic Sbox
            k = piRoundkey[i] % unWSBoxSz;                                      // -Selecting a 'random' number and applying mod unWSBoxSz
            this->dinSBox[j] = buffer[k];                                       // -Selecting and available entry
            buffer[k] = buffer[unWSBoxSz - 1];                                  // -Substituting old value with one not used yet
        }
    for(i = 0; i < SBOX_SIZE; i++ ) this->dinSboxInv[dinSBox[i]] = i;           // -Building dinamic Sbox inverse
}
```

#  Compilation

### Before doing anything, I am assuming:

1. You have installed GNU ``g++`` compiler.
2. The command-line interface software GNU ``Make`` is installed in your computer.

In order to check if you have ``g++`` available you can run:

- For Windows:
    - Open command prompt; one way to do this is searching *cmd* in Start menu.
    - Type ``g++ --version`` and press enter.

- For macOS and Linux:
    - Open terminal application.
    - Type ``g++ --version`` and press enter.

If you do not have this compiler installed, I strongly recommend you to install the GNU compiler collection (GCC). Installation
instructions can be found here:
[Linux](https://www.geeksforgeeks.org/how-to-install-gcc-compiler-on-linux/), 
[MacOS](https://cs.millersville.edu/~gzoppetti/InstallingGccMac.html),
[Windows](https://www.ibm.com/docs/en/devops-test-embedded/9.0.0?topic=overview-installing-recommended-gnu-compiler-windows).

To verify if you hame GNU ``make`` installed:

- For Linux and macOS:
    - Open terminal application.
    - Type ``make --version``

To install GNU ``make``, you can follow the instructions of the following links:
[Windows](https://stackoverflow.com/a/57042516), 
[MacOS](https://ipv6.rs/tutorial/macOS/GNU_Make/)

## Use make commands

**Note**: Executables will be located in [Executables](Apps/Executables) directory.

Use ``make`` commands to build the executables.

1. ``make AESencryption.exe`` to build executable for encryption.
2. ``make AESdecryption.exe`` to build executable for decryption.
3. ``make`` to build both.

Optionally, you can run the following commands on your terminal (command prompt on Windows)

For AESencryption.exe:
```
# This is, literally, the command that "make AESencryption.exe" calls.
g++ -o Apps/Executables/AESencryption.exe -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors -ggdb
-fno-omit-frame-pointer -O2 -std=c++2a Apps/encryption.cpp Apps/Settings.cpp Source/*.cpp
```

For AESdecryption.exe:
```
# This is, literally, the command that "make AESdecryption.exe" calls.
g++ -o Apps/Executables/AESdecryption.exe -Wall -Weffc++ -Wextra -Wsign-conversion -pedantic-errors -ggdb
-fno-omit-frame-pointer -O2 -std=c++2a Apps/decryption.cpp Apps/Settings.cpp Source/*.cpp
```

These last two commands are convenient if you do not have ``make`` installed.
