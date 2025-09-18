#ifndef ENCRYPTOR_HPP
#define ENCRYPTOR_HPP

#include <vector>
#include <cstdint>

/**
 * @class Encryptor
 * @brief An interface (abstract base class) for cryptographic transformations.
 * * Any class that implements this interface can be used with FileBase::apply_transformation.
 */
class Encryptor {
public:
    virtual ~Encryptor() = default;

    /**
     * @brief Encrypts a block of data in-place.
     * @param input The input to be transformed.
     * @param output The vector where the encrypted data will be written
     * * The 'const' on the method means the Encryptor object itself is not modified,
     * but the data it points to is.
     */
    virtual void encryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) const = 0; // Pure virtual function

    /**
     * @brief Decrypts a block of data in-place.
     * @param input The input to be transformed.
     * @param output The vector where the decrypted data will be written
     * * The 'const' on the method means the Encryptor object itself is not modified,
     * but the data it points to is.
     */
    virtual void decryption(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) const = 0; // Pure virtual function
};

#endif // ENCRYPTOR_HPP