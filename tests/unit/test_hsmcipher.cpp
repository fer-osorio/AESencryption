#include <gtest/gtest.h>
#include <cstring>
#include <filesystem>
#include "../../testing/include/test-vectors/fips197_cipher.hpp"
#include "../../testing/include/test-vectors/sp800_38a_modes.hpp"

#include "../../hsm-integration/include/hsm_session.hpp"
#include "../../hsm-integration/include/hsm_cipher.hpp"
#include "../../hsm-integration/include/hsm_key_handle.hpp"
#include "../../core-crypto/include/cipher.hpp"
#include "../../core-crypto/include/key.hpp"

extern "C" {
#include "../../core-crypto/aes/include/operation_modes.h"
#include "../../core-crypto/aes/include/key_expansion.h"
}

#include <vector>
#include <string>

namespace TV  = TestVectors::AES;
namespace SP  = TestVectors::AES::SP800_38A;
namespace F97 = TestVectors::AES::FIPS197::Cipher;

using CipherFortis::Key;
using CipherFortis::Cipher;
using namespace CipherFortis::HSM;

static const std::string LIB_PATH    = "/usr/lib64/pkcs11/libsofthsm2.so";
static const std::string TOKEN_LABEL = "AESdev";
static const std::string USER_PIN    = "1234";
static const TV::KeySize KS          = TV::KeySize::AES128;

// ── Helpers ───────────────────────────────────────────────────────────────────

// Imports a known plaintext key into the HSM as a session object.
// CKA_TOKEN=False: destroyed automatically on session close.
// CKA_SENSITIVE=False: required to import known plaintext (test-only).
static HSMKeyHandle importTestKey(
    HSMSession&        session,
    const uint8_t*     key_bytes,
    size_t             key_len_bytes,
    const std::string& label
) {
    CK_BBOOL        yes = CK_TRUE, no = CK_FALSE;
    CK_KEY_TYPE     aes = CKK_AES;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,       &cls, sizeof(cls) },
        { CKA_KEY_TYPE,    &aes, sizeof(aes) },
        { CKA_VALUE,       const_cast<uint8_t*>(key_bytes), static_cast<CK_ULONG>(key_len_bytes) },
        { CKA_TOKEN,       &no,  sizeof(no)  },
        { CKA_SENSITIVE,   &no,  sizeof(no)  },
        { CKA_EXTRACTABLE, &yes, sizeof(yes) },
        { CKA_ENCRYPT,     &yes, sizeof(yes) },
        { CKA_DECRYPT,     &yes, sizeof(yes) },
        { CKA_LABEL, const_cast<char*>(label.c_str()), static_cast<CK_ULONG>(label.size()) },
    };

    CK_OBJECT_HANDLE handle;
    CK_RV rv = session.p11()->C_CreateObject(
        session.session(), tmpl, sizeof(tmpl) / sizeof(*tmpl), &handle
    );
    if (rv != CKR_OK)
        throw PKCS11Exception("C_CreateObject (test import)", rv);

    Key::LengthBits lb;
    switch (key_len_bytes * 8) {
        case 192: lb = Key::LengthBits::_192; break;
        case 256: lb = Key::LengthBits::_256; break;
        default:  lb = Key::LengthBits::_128; break;
    }
    return HSMKeyHandle(handle, label, "", lb);
}

static size_t keyExpansionSize(size_t key_bits) {
    switch (key_bits) {
        case 192: return 208;
        case 256: return 240;
        default:  return 176;
    }
}

// ── Fixture ───────────────────────────────────────────────────────────────────

class HSMCipherTest : public ::testing::Test {
protected:
    void SetUp() override {
        if (!std::filesystem::exists(LIB_PATH)) {
            GTEST_SKIP() << "SoftHSM2 library not found at " << LIB_PATH;
        }
    }
};

// ── Part 1: NIST vector tests ─────────────────────────────────────────────────

TEST_F(HSMCipherTest, NistEcbEncrypt) {
    SCOPED_TRACE("NIST ECB Encrypt (FIPS 197)");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::ECB);

        auto vec      = F97::create(KS);
        auto key_vec  = vec->getKey();
        auto input    = vec->getInput();
        auto expected = vec->getExpectedOutput();

        HSMKeyHandle key = importTestKey(
            session, reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_vec.size(), "nist-ecb-enc");
        cipher.setActiveKey(key);

        std::vector<uint8_t> output;
        cipher.encryption(
            std::vector<uint8_t>(input.begin(), input.end()), output);

        EXPECT_EQ(0, memcmp(
            reinterpret_cast<const uint8_t*>(expected.data()),
            output.data(), expected.size()))
            << "ECB ciphertext matches FIPS 197 expected";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

TEST_F(HSMCipherTest, NistEcbDecrypt) {
    SCOPED_TRACE("NIST ECB Decrypt (FIPS 197)");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::ECB);

        auto vec      = F97::create(KS, TV::Direction::Decrypt);
        auto key_vec  = vec->getKey();
        auto input    = vec->getInput();
        auto expected = vec->getExpectedOutput();

        HSMKeyHandle key = importTestKey(
            session, reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_vec.size(), "nist-ecb-dec");
        cipher.setActiveKey(key);

        std::vector<uint8_t> output;
        cipher.decryption(
            std::vector<uint8_t>(input.begin(), input.end()), output);

        EXPECT_EQ(0, memcmp(
            reinterpret_cast<const uint8_t*>(expected.data()),
            output.data(), expected.size()))
            << "ECB plaintext matches FIPS 197 expected";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

TEST_F(HSMCipherTest, NistCbcEncryptMatchesNist) {
    SCOPED_TRACE("NIST CBC Encrypt (SP 800-38A)");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::CBC);

        auto vec      = SP::CBC::create(KS);
        auto key_vec  = vec->getKey();
        auto input    = vec->getInput();
        auto iv_vec   = vec->getIV();
        auto expected = vec->getExpectedOutput();

        HSMKeyHandle key = importTestKey(
            session, reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_vec.size(), "nist-cbc-enc");
        cipher.setActiveKey(key);
        cipher.setIV(std::vector<uint8_t>(iv_vec.begin(), iv_vec.end()));

        std::vector<uint8_t> output;
        cipher.encryption(
            std::vector<uint8_t>(input.begin(), input.end()), output);

        // CKM_AES_CBC_PAD appends a PKCS#7 padding block; NIST vectors do not.
        // Compare only the first kDataSize bytes.
        EXPECT_EQ(0, memcmp(
            reinterpret_cast<const uint8_t*>(expected.data()),
            output.data(), SP::kDataSize))
            << "CBC first 64 bytes match SP 800-38A expected";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

TEST_F(HSMCipherTest, NistCbcRoundtrip) {
    SCOPED_TRACE("NIST CBC Roundtrip (SP 800-38A)");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::CBC);

        auto vec     = SP::CBC::create(KS);
        auto key_vec = vec->getKey();
        auto input   = vec->getInput();
        auto iv_vec  = vec->getIV();

        HSMKeyHandle key = importTestKey(
            session, reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_vec.size(), "nist-cbc-rt");
        cipher.setActiveKey(key);
        cipher.setIV(std::vector<uint8_t>(iv_vec.begin(), iv_vec.end()));

        std::vector<uint8_t> ciphertext, recovered;
        cipher.encryption(std::vector<uint8_t>(input.begin(), input.end()),
                          ciphertext);
        cipher.decryption(ciphertext, recovered);

        // CKM_AES_CBC_PAD strips padding on decrypt — result equals original.
        EXPECT_EQ(0, memcmp(
            reinterpret_cast<const uint8_t*>(input.data()),
            recovered.data(), SP::kDataSize))
            << "CBC roundtrip preserves plaintext";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

/* Uncomment only with confirmation of OFB mode support
TEST_F(HSMCipherTest, NistOfbEncryptMatchesNist) { ... }
TEST_F(HSMCipherTest, NistOfbRoundtrip) { ... }
*/

TEST_F(HSMCipherTest, NistCtrRoundtrip) {
    SCOPED_TRACE("NIST CTR Roundtrip (SP 800-38A)");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::CTR);

        auto vec     = SP::CTR::create(KS);
        auto key_vec = vec->getKey();
        auto input   = vec->getInput();
        auto ctr_vec = vec->getCounter();

        HSMKeyHandle key = importTestKey(
            session, reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_vec.size(), "nist-ctr-rt");
        cipher.setActiveKey(key);
        cipher.setIV(std::vector<uint8_t>(ctr_vec.begin(), ctr_vec.end()));

        std::vector<uint8_t> ciphertext, recovered;
        cipher.encryption(std::vector<uint8_t>(input.begin(), input.end()),
                          ciphertext);
        cipher.decryption(ciphertext, recovered);

        EXPECT_EQ(0, memcmp(
            reinterpret_cast<const uint8_t*>(input.data()),
            recovered.data(), SP::kDataSize))
            << "CTR roundtrip preserves plaintext";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

// ── Part 2: Cross-path comparison tests ──────────────────────────────────────
//
// Same plaintext and key through both HSMCipher (PKCS#11) and the C functions
// (operation_modes.h). Outputs must be identical.

TEST_F(HSMCipherTest, CrosspathEcb) {
    SCOPED_TRACE("Cross-path ECB (HSMCipher vs C encryptECB)");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::ECB);

        auto vec      = F97::create(KS);
        auto key_vec  = vec->getKey();
        auto input_uc = vec->getInput();
        std::vector<uint8_t> input(input_uc.begin(), input_uc.end());
        size_t key_bits = key_vec.size() * 8;

        // HSM path
        HSMKeyHandle key = importTestKey(
            session, reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_vec.size(), "cp-ecb");
        cipher.setActiveKey(key);
        std::vector<uint8_t> hsm_output;
        cipher.encryption(input, hsm_output);

        // C path
        std::vector<uint8_t> ke(keyExpansionSize(key_bits));
        EXPECT_EQ(static_cast<int>(NoException), static_cast<int>(KeyExpansionInitWrite(
            reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_bits, ke.data(), false)))
            << "C KeyExpansionInitWrite succeeded";

        std::vector<uint8_t> c_output(input.size());
        EXPECT_EQ(static_cast<int>(NoException), static_cast<int>(encryptECB(
            input.data(), input.size(), ke.data(), key_bits, c_output.data())))
            << "C encryptECB succeeded";

        EXPECT_EQ(0, memcmp(hsm_output.data(), c_output.data(), input.size()))
            << "ECB: HSMCipher output matches C implementation";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

TEST_F(HSMCipherTest, CrosspathCbc) {
    // CKM_AES_CBC_PAD adds a PKCS#7 padding block; encryptCBC does not.
    // Only the first kDataSize (64) bytes are compared.
    SCOPED_TRACE("Cross-path CBC (HSMCipher vs C encryptCBC)");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::CBC);

        auto vec      = SP::CBC::create(KS);
        auto key_vec  = vec->getKey();
        auto input_uc = vec->getInput();
        auto iv_uc    = vec->getIV();
        std::vector<uint8_t> input(input_uc.begin(), input_uc.end());
        std::vector<uint8_t> iv(iv_uc.begin(), iv_uc.end());
        size_t key_bits = key_vec.size() * 8;

        // HSM path
        HSMKeyHandle key = importTestKey(
            session, reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_vec.size(), "cp-cbc");
        cipher.setActiveKey(key);
        cipher.setIV(iv);
        std::vector<uint8_t> hsm_output;
        cipher.encryption(input, hsm_output);

        // C path
        std::vector<uint8_t> ke(keyExpansionSize(key_bits));
        EXPECT_EQ(static_cast<int>(NoException), static_cast<int>(KeyExpansionInitWrite(
            reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_bits, ke.data(), false)))
            << "C KeyExpansionInitWrite succeeded";

        std::vector<uint8_t> c_output(input.size());
        EXPECT_EQ(static_cast<int>(NoException), static_cast<int>(encryptCBC(
            input.data(), input.size(), ke.data(), key_bits,
            iv.data(), c_output.data())))
            << "C encryptCBC succeeded";

        EXPECT_EQ(0, memcmp(hsm_output.data(), c_output.data(), SP::kDataSize))
            << "CBC first 64 bytes: HSMCipher matches C implementation";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

/* Uncomment only with confirmation of OFB mode support
TEST_F(HSMCipherTest, CrosspathOfb) { ... }
*/

TEST_F(HSMCipherTest, CrosspathCtr) {
    // Single-block (16 bytes) input — no counter increment occurs.
    // Both HSMCipher (CKM_AES_CTR, 128-bit big-endian increment) and
    // encryptCTR (64-bit little-endian increment) use the initial counter
    // value exactly once and agree on the keystream for the first block.
    SCOPED_TRACE("Cross-path CTR single-block (HSMCipher vs C encryptCTR)");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::CTR);

        auto vec      = SP::CTR::create(KS);
        auto key_vec  = vec->getKey();
        auto input_uc = vec->getInput();
        auto ctr_uc   = vec->getCounter();
        // Use first block only to avoid counter-format divergence.
        std::vector<uint8_t> input(input_uc.begin(), input_uc.begin() + 16);
        std::vector<uint8_t> ctr(ctr_uc.begin(), ctr_uc.end());
        size_t key_bits = key_vec.size() * 8;

        // HSM path
        HSMKeyHandle key = importTestKey(
            session, reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_vec.size(), "cp-ctr");
        cipher.setActiveKey(key);
        cipher.setIV(ctr);
        std::vector<uint8_t> hsm_output;
        cipher.encryption(input, hsm_output);

        // C path
        std::vector<uint8_t> ke(keyExpansionSize(key_bits));
        EXPECT_EQ(static_cast<int>(NoException), static_cast<int>(KeyExpansionInitWrite(
            reinterpret_cast<const uint8_t*>(key_vec.data()),
            key_bits, ke.data(), false)))
            << "C KeyExpansionInitWrite succeeded";

        std::vector<uint8_t> c_output(16);
        EXPECT_EQ(static_cast<int>(NoException), static_cast<int>(encryptCTR(
            input.data(), 16, ke.data(), key_bits,
            ctr.data(), c_output.data())))
            << "C encryptCTR succeeded";

        EXPECT_EQ(0, memcmp(hsm_output.data(), c_output.data(), 16))
            << "CTR first block: HSMCipher output matches C implementation";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

// ── Part 3: Key lifecycle tests ───────────────────────────────────────────────

TEST_F(HSMCipherTest, GenerateKeyNotExtractable) {
    SCOPED_TRACE("Key lifecycle: CKA_EXTRACTABLE=False after generateKey");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::ECB);

        HSMKeyHandle key = cipher.generateKey(Key::LengthBits::_256, "test-gen-256");
        EXPECT_TRUE(key.isValid()) << "Generated key handle is valid";

        // Read CKA_EXTRACTABLE back from the token — must be CK_FALSE.
        CK_BBOOL extractable = CK_TRUE;
        CK_ATTRIBUTE check[] = {
            { CKA_EXTRACTABLE, &extractable, sizeof(extractable) }
        };
        session.p11()->C_GetAttributeValue(
            session.session(), key.handle(), check, 1);

        EXPECT_TRUE(extractable == CK_FALSE)
            << "CKA_EXTRACTABLE is False — key cannot be exported";

        cipher.destroyKey(key);
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

TEST_F(HSMCipherTest, FindKeyReturnsValidHandle) {
    SCOPED_TRACE("Key lifecycle: findKey returns valid handle");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::ECB);

        cipher.generateKey(Key::LengthBits::_128, "findable-key");
        HSMKeyHandle found = cipher.findKey("findable-key");
        EXPECT_TRUE(found.isValid()) << "Found key handle is valid";

        cipher.destroyKey(found);
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}

TEST_F(HSMCipherTest, DestroyKeyNotFound) {
    SCOPED_TRACE("Key lifecycle: destroyed key is no longer findable");
    try {
        HSMSession session(LIB_PATH, TOKEN_LABEL, USER_PIN);
        HSMCipher  cipher(session, Cipher::OperationMode::Identifier::ECB);

        cipher.generateKey(Key::LengthBits::_128, "ephemeral-key");
        HSMKeyHandle key = cipher.findKey("ephemeral-key");
        cipher.destroyKey(key);

        bool threw = false;
        try { cipher.findKey("ephemeral-key"); }
        catch (const std::runtime_error&) { threw = true; }

        EXPECT_TRUE(threw) << "findKey throws after key is destroyed";
    } catch (const std::exception& e) {
        FAIL() << "Exception: " << e.what();
    }
}
