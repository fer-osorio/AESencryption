#include "../include/hsm_cipher.hpp"

#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace AESencryption {
namespace HSM {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string bytesToHex(const std::vector<CK_BYTE>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes)
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(b);
    return oss.str();
}

void HSMCipher::checkRV(const std::string& fn, CK_RV rv) const {
    if (rv != CKR_OK) throw PKCS11Exception(fn, rv);
}

void HSMCipher::checkActiveKey() const {
    if (!active_key_ || !active_key_->isValid())
        throw std::runtime_error("HSMCipher: no active key set");
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

HSMCipher::HSMCipher(
    HSMSession& session, Cipher::OperationMode::Identifier mode
) :
    session_(session), mode_(mode)
{}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

HSMKeyHandle HSMCipher::generateKey(Key::LengthBits length, const std::string& label) {
    CK_BBOOL      yes      = CK_TRUE,  no = CK_FALSE;
    CK_KEY_TYPE   aes_type = CKK_AES;
    CK_OBJECT_CLASS cls    = CKO_SECRET_KEY;
    CK_ULONG      key_bytes = static_cast<CK_ULONG>(static_cast<int>(length) / 8);

    // Random 4-byte object ID — distinguishes objects with the same label.
    std::vector<CK_BYTE> id(4);
    checkRV(
        "C_GenerateRandom",
        session_.p11()->C_GenerateRandom(
            session_.session(), id.data(), 4
        )
    );

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &cls,      sizeof(cls)       },
        { CKA_KEY_TYPE,    &aes_type, sizeof(aes_type)  },
        { CKA_VALUE_LEN,   &key_bytes,sizeof(key_bytes) },
        { CKA_TOKEN,       &yes,      sizeof(yes)       },
        { CKA_SENSITIVE,   &yes,      sizeof(yes)       },
        { CKA_EXTRACTABLE, &no,       sizeof(no)        },
        { CKA_ENCRYPT,     &yes,      sizeof(yes)       },
        { CKA_DECRYPT,     &yes,      sizeof(yes)       },
        { CKA_LABEL, const_cast<char*>(label.c_str()), static_cast<CK_ULONG>(label.size()) },
        { CKA_ID,    id.data(), static_cast<CK_ULONG>(id.size())   },
    };

    CK_MECHANISM     gen_mech = { CKM_AES_KEY_GEN, nullptr, 0 };
    CK_OBJECT_HANDLE handle;
    checkRV(
        "C_GenerateKey",
        session_.p11()->C_GenerateKey(
            session_.session(), &gen_mech,
            tmpl, sizeof(tmpl) / sizeof(*tmpl),
            &handle
        )
    );

    return HSMKeyHandle(handle, label, bytesToHex(id), length);
}

HSMKeyHandle HSMCipher::findKey(const std::string& label) {
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;

    CK_ATTRIBUTE search[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_LABEL, const_cast<char*>(label.c_str()), static_cast<CK_ULONG>(label.size()) },
    };

    checkRV(
        "C_FindObjectsInit",
        session_.p11()->C_FindObjectsInit(
            session_.session(), search, sizeof(search) / sizeof(*search)
        )
    );

    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
    CK_ULONG         found  = 0;
    CK_RV rv = session_.p11()->C_FindObjects(session_.session(), &handle, 1, &found);

    session_.p11()->C_FindObjectsFinal(session_.session());
    checkRV("C_FindObjects", rv);

    if (found == 0)
        throw std::runtime_error("HSMCipher: key not found: " + label);

    // Read the key length back from the token.
    CK_ULONG value_len = 0;
    CK_ATTRIBUTE len_attr[] = {
        { CKA_VALUE_LEN, &value_len, sizeof(value_len) },
    };
    checkRV(
        "C_GetAttributeValue",
        session_.p11()->C_GetAttributeValue(
            session_.session(), handle, len_attr, 1
        )
    );

    Key::LengthBits length;
    switch (value_len * 8) {
        case 192: length = Key::LengthBits::_192; break;
        case 256: length = Key::LengthBits::_256; break;
        default:  length = Key::LengthBits::_128; break;
    }

    return HSMKeyHandle(handle, label, "", length);
}

void HSMCipher::destroyKey(const HSMKeyHandle& key) {
    checkRV(
        "C_DestroyObject", session_.p11()->C_DestroyObject(session_.session(), key.handle())
    );
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

void HSMCipher::setActiveKey(const HSMKeyHandle& key) {
    active_key_ = &key;
}

void HSMCipher::setIV(const std::vector<uint8_t>& iv) {
    if (iv.size() != 16)
        throw std::invalid_argument("HSMCipher: IV must be exactly 16 bytes");
    iv_ = iv;
}

// ---------------------------------------------------------------------------
// Mechanism builder
// ---------------------------------------------------------------------------

CK_MECHANISM HSMCipher::buildMechanism() const {
    switch (mode_) {
        case Cipher::OperationMode::Identifier::ECB:
            return { CKM_AES_ECB, nullptr, 0 };

        case Cipher::OperationMode::Identifier::CBC:
            if (iv_.size() != 16)
                throw std::invalid_argument(
                    "HSMCipher: CBC mode requires a 16-byte IV"
                );
            // iv_.data() is stable for the duration of the synchronous call.
            return { CKM_AES_CBC_PAD,
                     const_cast<uint8_t*>(iv_.data()),
                     static_cast<CK_ULONG>(iv_.size()) };

        case Cipher::OperationMode::Identifier::OFB:
            throw std::invalid_argument("OFB mode is not supported by this PKCS#11 token");
            /*if (iv_.size() != 16)  Uncomment only with confirmation of OFB mode support
                throw std::invalid_argument(
                    "HSMCipher: OFB mode requires a 16-byte IV"
                );
            return { CKM_AES_OFB,
                     const_cast<uint8_t*>(iv_.data()),
                     static_cast<CK_ULONG>(iv_.size()) };*/

        case Cipher::OperationMode::Identifier::CTR: {
            if (iv_.size() != 16)
                throw std::invalid_argument(
                    "HSMCipher: CTR mode requires a 16-byte IV"
                );
            // CK_AES_CTR_PARAMS: 128-bit counter width, initial counter = IV.
            static thread_local CK_AES_CTR_PARAMS ctr_params;
            ctr_params.ulCounterBits = 128;
            std::copy(iv_.begin(), iv_.end(), ctr_params.cb);
            return { CKM_AES_CTR,
                     &ctr_params,
                     sizeof(ctr_params) };
        }

        default:
            throw std::invalid_argument(
                "HSMCipher: unsupported operation mode"
            );
    }
}

// ---------------------------------------------------------------------------
// Encryptor interface
// ---------------------------------------------------------------------------

void HSMCipher::encryption(
    const std::vector<uint8_t>& input, std::vector<uint8_t>& output
) const {
    checkActiveKey();
    CK_MECHANISM mech = buildMechanism();

    checkRV(
        "C_EncryptInit",
        session_.p11()->C_EncryptInit(
            session_.session(), &mech, active_key_->handle()
        )
    );

    // Allocate enough for input + one padding block.
    CK_ULONG out_len = static_cast<CK_ULONG>(input.size() + 16);
    output.resize(out_len);

    checkRV(
        "C_Encrypt",
        session_.p11()->C_Encrypt(
            session_.session(),
            const_cast<CK_BYTE_PTR>(input.data()),
            static_cast<CK_ULONG>(input.size()),
            output.data(),
            &out_len
        )
    );

    output.resize(out_len);
}

void HSMCipher::decryption(
    const std::vector<uint8_t>& input, std::vector<uint8_t>& output
) const {
    checkActiveKey();
    CK_MECHANISM mech = buildMechanism();

    checkRV(
        "C_DecryptInit",
        session_.p11()->C_DecryptInit(
            session_.session(), &mech, active_key_->handle()
        )
    );

    CK_ULONG out_len = static_cast<CK_ULONG>(input.size());
    output.resize(out_len);

    checkRV(
        "C_Decrypt",
        session_.p11()->C_Decrypt(
            session_.session(),
            const_cast<CK_BYTE_PTR>(input.data()),
            static_cast<CK_ULONG>(input.size()),
            output.data(),
            &out_len
        )
    );

    output.resize(out_len);
}

} // namespace HSM
} // namespace AESencryption
