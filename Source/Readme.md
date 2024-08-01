# Notes to the developer

## Adding a new operation mode.
-   When developing a new operation mode, do not forget to update the Key structure (present in the AES.hpp file) by adding this new operation mode in the
    enumeration ``OperationMode``.
-   In its coding, one of the first things that must be done is to set the argument of type ``OperationMode`` in the Key object with the new value described in the
    past point. This can be done with the line ``this->key.set_OperationMode(Key::<NewOperationMode>);``.
-   Friend functions are used for the encryption and decryption of files because, through this method, one single ``AES::Cipher`` object can encrypt multiple files.
