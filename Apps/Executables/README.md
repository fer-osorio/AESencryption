#  Compilation

Use ``make`` commands to build the executables.

1. ``make AESencryption.exe`` to build executable for encryption.
2. ``make AESencryption.exe`` to build executable for decryption.
3. ``make`` to build both.

### Passing arguments to the executable.
We can pass arguments to the executables to encrypt/decrypt a single file. Set as first argument the name/path of the encryption key we want to use followed by the fiele (.bmp or .txt) we want to encrypt as second argument, this will encrypt/decrypt your file passed as second argument using the key regferenced in the first arguemt.

**Example:**

1. Encryption; executing ``./AESencryption.exe AESencryption.key Pic01.bmp``.

![Encryption](../../Images/AESencryption.gif)

2. Decryption; executing ``./AESdecryption.exe AESencryption.key Text00.txt``.

![Decryption](../../Images/AESdecryption.gif)

