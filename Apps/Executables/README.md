#  Compilation

Use ``make`` commands to build the executables.

1. ``make AESencryption.exe`` to build executable for encryption.
2. ``make AESencryption.exe`` to build executable for decryption.
3. ``make`` to build both.

### Passing arguments to the executables.
We can pass arguments to the executables to encrypt/decrypt a single file. Set as first argument the name/path of the encryption
key we want to use followed by the files (currently supported) that are meant to be encrypted as the following arguments, this
will encrypt/decrypt the files using the key referenced in the first argument.

**Example:**

Note: Videos were edited to decrease the size of these gifts.

1. Executing ``./AESencryption.exe AESencryption.aeskey Files_for_testing/Pic00.bmp Files_for_testing/Pic01.bmp``.

![Encryption](../../Images/AESencryption.gif)

2. Executing ``./AESdecryption.exe AESencryption.aeskey Files_for_testing/Text00.txt Files_for_testing/Text01.txt``.

![Decryption](../../Images/AESdecryption.gif)

