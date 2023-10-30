# AES

AES implementation in C++.

An implementation of AES is developed to encrypt an array of bytes (char's) with a know length; then, it is used for the encryption of BMP images.

#   Usage

##  Executables
Supousing we are in the "Executable" directory, we can use the executables un the following ways

### Input from command line interface (CLI).
Run the commnad `./encrypt` to encrypt text from the CLI.

### BMP images.
Execute the file `encrypt` and pass the name of the image you want to encrypt as an argument, for example `./encrypt Test00.bmp`. This will encrypt your image and will write the used key in a binary file with a `.key` extension. If CBC mode was used (witch it will since is the unique one avaible now), then the initial vector (IV) will be writed in the same file.

For the decryption, execute pass the name of the file containing the key (.key file) as first argument and the name of the BMP image as second argument, for example `./decryp Test00.key Test00.bmp`.

# Important notes:
* Right now the unique operation mode that is implemented is CBC (Cipher Block Chaining).
* The padding problem for the CBC mode is solved with a method not specified in the NIST standard.
* No attempt to generate secure cryptographic keys is made. 
