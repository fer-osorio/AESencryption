# AES

Encryption of BMP images using an implementation of AES (Advance encryption 
Standard) in C++.

Important notes:
    *Right now the unique operation mode that is implemented is [CBC].
    *The padding problem for the CBC mode is solved with a method not specified
     NIST standard.
    *No attempt to generate secure cryptographic keys is made. 
