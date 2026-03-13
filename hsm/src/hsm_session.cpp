#include "hsm_session.hpp"

#include <dlfcn.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>

namespace AESencryption {
namespace HSM {

// ---------------------------------------------------------------------------
// PKCS11Exception
// ---------------------------------------------------------------------------

PKCS11Exception::PKCS11Exception(const std::string& function, CK_RV rv)
    : std::runtime_error([&]() {
          std::ostringstream oss;
          oss << function << " failed with CKR code 0x"
              << std::hex << std::uppercase << std::setfill('0')
              << std::setw(8) << static_cast<unsigned long>(rv);
          return oss.str();
      }()),
      rv_(rv) {}

// ---------------------------------------------------------------------------
// HSMSession — helpers
// ---------------------------------------------------------------------------

void HSMSession::checkRV(const std::string& fn, CK_RV rv) const {
    if (rv != CKR_OK) throw PKCS11Exception(fn, rv);
}

CK_SLOT_ID HSMSession::findSlotByLabel(const std::string& label) const {
    CK_ULONG count = 0;
    checkRV("C_GetSlotList (size)", p11_->C_GetSlotList(CK_TRUE, nullptr, &count));

    if (count == 0) throw PKCS11Exception("C_GetSlotList", CKR_TOKEN_NOT_PRESENT);

    std::vector<CK_SLOT_ID> slots(count);
    checkRV("C_GetSlotList (fill)", p11_->C_GetSlotList(CK_TRUE, slots.data(), &count));

    for (CK_SLOT_ID slot : slots) {
        CK_TOKEN_INFO info;
        if (p11_->C_GetTokenInfo(slot, &info) != CKR_OK) continue;

        // PKCS#11 pads the label field to 32 bytes with trailing spaces.
        std::string raw(reinterpret_cast<const char*>(info.label),
                        sizeof(info.label));
        // Trim trailing spaces.
        auto end = raw.find_last_not_of(' ');
        std::string trimmed = (end == std::string::npos) ? "" : raw.substr(0, end + 1);

        if (trimmed == label) return slot;
    }

    throw PKCS11Exception("findSlotByLabel", CKR_TOKEN_NOT_PRESENT);
}

// ---------------------------------------------------------------------------
// HSMSession — constructor / destructor / move
// ---------------------------------------------------------------------------

HSMSession::HSMSession(const std::string& lib_path,
                       const std::string& token_label,
                       const std::string& user_pin)
{
    // 1. Load the PKCS#11 shared library.
    lib_handle_ = dlopen(lib_path.c_str(), RTLD_NOW);
    if (!lib_handle_) {
        throw std::runtime_error(std::string("dlopen failed: ") + dlerror());
    }

    // 2. Resolve C_GetFunctionList and obtain the function-list pointer.
    using GetFunctionList_t = CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR);
    auto get_fn_list = reinterpret_cast<GetFunctionList_t>(
        dlsym(lib_handle_, "C_GetFunctionList"));
    if (!get_fn_list) {
        dlclose(lib_handle_);
        lib_handle_ = nullptr;
        throw std::runtime_error(std::string("dlsym(C_GetFunctionList) failed: ") + dlerror());
    }

    CK_RV rv = get_fn_list(&p11_);
    if (rv != CKR_OK || !p11_) {
        dlclose(lib_handle_);
        lib_handle_ = nullptr;
        throw PKCS11Exception("C_GetFunctionList", rv != CKR_OK ? rv : CKR_GENERAL_ERROR);
    }

    // 3. Initialise the library.
    checkRV("C_Initialize", p11_->C_Initialize(nullptr));

    // 4. Find the slot that holds the requested token.
    CK_SLOT_ID slot = findSlotByLabel(token_label);

    // 5. Open a R/W serial session.
    checkRV("C_OpenSession",
            p11_->C_OpenSession(slot,
                                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                nullptr, nullptr,
                                &session_));

    // 6. Log in as the normal user.
    auto* pin     = reinterpret_cast<CK_UTF8CHAR_PTR>(
                        const_cast<char*>(user_pin.c_str()));
    auto  pin_len = static_cast<CK_ULONG>(user_pin.size());
    checkRV("C_Login", p11_->C_Login(session_, CKU_USER, pin, pin_len));
}

HSMSession::~HSMSession() {
    if (session_ != CK_INVALID_HANDLE) {
        p11_->C_Logout(session_);
        p11_->C_CloseSession(session_);
        session_ = CK_INVALID_HANDLE;
    }
    if (p11_) {
        p11_->C_Finalize(nullptr);
        p11_ = nullptr;
    }
    if (lib_handle_) {
        dlclose(lib_handle_);
        lib_handle_ = nullptr;
    }
}

HSMSession::HSMSession(HSMSession&& other) noexcept
    : lib_handle_(other.lib_handle_),
      p11_(other.p11_),
      session_(other.session_)
{
    other.lib_handle_ = nullptr;
    other.p11_        = nullptr;
    other.session_    = CK_INVALID_HANDLE;
}

} // namespace HSM
} // namespace AESencryption
