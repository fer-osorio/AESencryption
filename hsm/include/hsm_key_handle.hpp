#ifndef HSM_KEY_HANDLE_HPP
#define HSM_KEY_HANDLE_HPP

#include <string>
#include <pkcs11.h>
#include "key.hpp"  // for Key::LengthBits — reuse existing enum

namespace AESencryption {
namespace HSM {

class HSMKeyHandle {
public:
    HSMKeyHandle(CK_OBJECT_HANDLE    handle,
                 const std::string&  label,
                 const std::string&  id_hex,
                 Key::LengthBits     length);

    // Default constructor produces an invalid handle.
    HSMKeyHandle() = default;

    CK_OBJECT_HANDLE   handle() const { return handle_; }
    const std::string& label()  const { return label_;  }
    const std::string& idHex()  const { return id_hex_; }
    Key::LengthBits    length() const { return length_;  }

    bool isValid() const { return handle_ != CK_INVALID_HANDLE; }

    // No method to retrieve key bytes — intentional.

private:
    CK_OBJECT_HANDLE handle_  = CK_INVALID_HANDLE;
    std::string      label_;
    std::string      id_hex_;
    Key::LengthBits  length_  = Key::LengthBits::_128;
};

} // namespace HSM
} // namespace AESencryption

#endif // HSM_KEY_HANDLE_HPP
