#ifndef HSM_SESSION_HPP
#define HSM_SESSION_HPP

#include <string>
#include <stdexcept>
#include <pkcs11.h>

namespace AESencryption {
namespace HSM {

// Thrown when any PKCS#11 function returns a code other than CKR_OK.
// Carries the function name and the raw CK_RV code for diagnostics.
class PKCS11Exception : public std::runtime_error {
public:
    PKCS11Exception(const std::string& function, CK_RV rv);
    CK_RV rv() const { return rv_; }
private:
    CK_RV rv_;
};

class HSMSession {
public:
    // Loads lib_path via dlopen, initialises the library, finds the token
    // by label, opens a R/W session, and logs in.
    // Throws PKCS11Exception on any failure.
    HSMSession(const std::string& lib_path,
               const std::string& token_label,
               const std::string& user_pin);

    // C_Logout -> C_CloseSession -> C_Finalize -> dlclose, in that order.
    ~HSMSession();

    // Non-copyable: a session is an exclusive resource.
    HSMSession(const HSMSession&)            = delete;
    HSMSession& operator=(const HSMSession&) = delete;

    // Movable: allows returning from factory functions.
    HSMSession(HSMSession&&) noexcept;

    CK_SESSION_HANDLE session() const { return session_; }
    CK_FUNCTION_LIST* p11()     const { return p11_;     }

private:
    void*             lib_handle_ = nullptr;
    CK_FUNCTION_LIST* p11_        = nullptr;
    CK_SESSION_HANDLE session_    = CK_INVALID_HANDLE;

    CK_SLOT_ID findSlotByLabel(const std::string& label) const;
    void       checkRV(const std::string& fn, CK_RV rv)  const;
};

} // namespace HSM
} // namespace AESencryption

#endif // HSM_SESSION_HPP
