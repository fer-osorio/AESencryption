# Notes to the developer

## Adding a new operation mode.
-   When developing a new operation mode, do not forget to update the Key structure (present in the AES.hpp file) by adding this new operation mode in the
    enumeration ``OperationMode``.
-   In the coding of the encryption function using this new operation mode, one of the first things that must be done is to set the argument of type
    ``OperationMode`` in the Key object with the new value described in the past point. This can be done with the line
    ``this->key.set_OperationMode(Key::<NewOperationMode>);``.
-   Friend functions are used for the encryption and decryption of files because, through this method, one single ``AES::Cipher`` object can encrypt multiple files.
-   Update the constructor ``Key::Key(const char*const fname)`` (construct a Key object from file) and the function ``void Key::save(const char* const fname) const``
    (saves the Key object into a binary file) for each new operation mode.
    
## To do.
-   Check if the Sbox using for decryption is the default one (the one specified int the NIST Standard) or is a modified one.
