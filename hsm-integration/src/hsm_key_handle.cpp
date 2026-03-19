#include "../include/hsm_key_handle.hpp"

namespace CipherFortis {
namespace HSM {

HSMKeyHandle::HSMKeyHandle(
    CK_OBJECT_HANDLE    handle,
    const std::string&  label,
    const std::string&  id_hex,
    Key::LengthBits     length
) :
    handle_(handle),
    label_(label),
    id_hex_(id_hex),
    length_(length)
{}

} // namespace HSM
} // namespace CipherFortis
