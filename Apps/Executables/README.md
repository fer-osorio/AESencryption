#  Compilation

Use ``make`` comands to build the executables.

1. ``make AESencryption.exe`` to build executable for encryption.
2. ``make AESencryption.exe`` to build executable for decryption.
3. ``make`` to build both.

### Passing arguments to the executable.
We can pass arguments to the executables to encrypt/decrypt a single file. Set as first argument the name/path of the encryption key we want to use followed by the fiele (.bmp or .txt) we want to encrypt as second argument, this will encrypt/decrypt your file passed as second argument using the key regferenced in the first arguemt.

**Example:**

Before executing ``./AESencryption.exe AESencryption.key Test01.bmp``.

![Before encryption](../../Images/BeforeEncryption.png)

The last action encrypts the image using ``AESencryption.key``.

![Before decryption](../../Images/BeforeDecryption.png)

Finally, we execute ``./AESencryption.exe AESencryption.key Test01.bmp``, retreaving the origial image.

![After decryption](../../Images/AfterDecryption.png)

