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
     * @brief Processes a block of data in-place.
     * @param data The data to be transformed. This vector will be modified.
     * * The 'const' on the method means the Encryptor object itself is not modified,
     * but the data it points to is.
     */
    virtual void process(std::vector<uint8_t>& data) const = 0; // Pure virtual function
};

#endif // ENCRYPTOR_HPP