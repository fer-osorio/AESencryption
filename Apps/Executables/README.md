#  Compilation

Use ``make`` commands to build the executables.

1. ``make AESencryption.exe`` to build executable for encryption.
2. ``make AESencryption.exe`` to build executable for decryption.
3. ``make`` to build both.

### Passing arguments to the executables.
We can pass arguments to the executables to encrypt/decrypt a single file. Set as first argument the name/path of the encryption
key we want to use followed by the files (currently supported) that are meant to be encrypted as the following arguments, this
will encrypt/decrypt the files using the key regferenced in the first arguemt.

**Example:**

1. Encryption; executing ``./AESencryption.exe AESencryption.key Pic01.bmp``.

![Encryption](../../Images/AESencryption.gif)

2. Decryption; executing ``./AESdecryption.exe AESencryption.key Text00.txt``.

![Decryption](../../Images/AESdecryption.gif)

