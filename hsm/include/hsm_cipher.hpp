#ifndef HSM_CIPHER_HPP
#define HSM_CIPHER_HPP

#include "../../include/encryptor.hpp"
#include "../../include/cipher.hpp"
#include "hsm_session.hpp"
#include "hsm_key_handle.hpp"

#include <vector>
#include <string>
#include <cstdint>

namespace AESencryption {
namespace HSM {

class HSMCipher : public Encryptor {
public:
    // session is held by reference — HSMCipher does not own it.
    // The caller must keep HSMSession alive for the lifetime of HSMCipher.
    HSMCipher(
        HSMSession& session,
        Cipher::OperationMode::Identifier mode
    );

    ~HSMCipher() override = default;

    // Non-copyable — session references and object handles are not
    // safely copyable.
    HSMCipher(const HSMCipher&)            = delete;
    HSMCipher& operator=(const HSMCipher&) = delete;

    // ── Key management ────────────────────────────────────────────────
    // CKA_SENSITIVE=True and CKA_EXTRACTABLE=False are enforced
    // unconditionally — not optional, not configurable.

    HSMKeyHandle generateKey(
        Key::LengthBits length, const std::string& label
    );

    // Throws std::runtime_error if no key with this label exists.
    HSMKeyHandle findKey(const std::string& label);

    // Permanently destroys the key object from the HSM.
    void destroyKey(const HSMKeyHandle& key);

    // ── Encryptor interface ───────────────────────────────────────────
    // setActiveKey() must be called before these.

    void encryption(
        const std::vector<uint8_t>& input, std::vector<uint8_t>& output
    ) const override;

    void decryption(
        const std::vector<uint8_t>& input, std::vector<uint8_t>& output
    ) const override;

    // ── Configuration ─────────────────────────────────────────────────

    void setActiveKey(const HSMKeyHandle& key);

    // Required for CBC, OFB, and CTR modes. Ignored for ECB.
    // Must be exactly 16 bytes.
    void setIV(const std::vector<uint8_t>& iv);

private:
    HSMSession&                       session_;
    Cipher::OperationMode::Identifier mode_;
    const HSMKeyHandle*               active_key_ = nullptr;
    std::vector<uint8_t>              iv_;

    CK_MECHANISM buildMechanism() const;
    void         checkActiveKey() const;
    void         checkRV(const std::string& fn, CK_RV rv) const;
};

} // namespace HSM
} // namespace AESencryption

#endif // HSM_CIPHER_HPP
