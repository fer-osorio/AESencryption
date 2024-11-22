# Notes to the developer

## Adding a new operation mode.
-   When developing a new operation mode, do not forget to update the Key structure (present in the AES.hpp file) by adding this
    new operation mode in the enumeration ``OperationMode``.
-   Update the constructor ``Key::Key(const char*const fname)`` (construct a Key object from file) and the function
    ``void Key::save(const char* const fname) const`` (saves the Key object into a binary file) for each new operation mode.

## Why friends
-   Friend functions are used for the encryption and decryption of files because, through this method, one single ``AES::Cipher``
    object can encrypt multiple files.
