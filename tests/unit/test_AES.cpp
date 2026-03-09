#include "../../test-framework/include/test-encryption/detail/block_cipher_tester.hpp"
#include "../../data-encryption/include/block.h"
#include "../../data-encryption/include/key_expansion.h"
#include "../../data-encryption/include/AES.h"

static KeyExpansion_t* (*allocateKeyExapansion)(size_t)      = KeyExpansionCreateZero;
static void            (*freeKeyExpansion)(KeyExpansion_t**) = KeyExpansionDestroy;
static Block_t*        (*allocateBlock)()                    = BlockCreateZero;
static void            (*freeBlock)(Block_t**)               = BlockDestroy;

CryptoTest::BlockCipher::MemoryCallbacks<KeyExpansion_t, Block_t> callbacks{
    allocateKeyExapansion,
    freeKeyExpansion,
    allocateBlock,
    freeBlock
};

CryptoTest::BlockCipher::TypeByteInterface<KeyExpansion_t, Block_t> byteInterface{
    [](const KeyExpansion_t*const input, size_t keySize,const uint8_t* bytes) -> bool{
        return compareKeyExpansionBytes(input, bytes);
    },
    [](KeyExpansion_t*const output, size_t keylenbits, const unsigned char*const input) -> int{
        return static_cast<int>(KeyExpansionReadFromBytes(output, input));
    },
    [](const Block_t*const input, const uint8_t* bytes) -> bool{
        return compareBlockBytes(input, bytes);
    },
    [](Block_t*const output, const unsigned char*const input) -> int {
        return static_cast<int>(BlockFromBytes(output, input));
    }
};

CryptoTest::BlockCipher::Tester<KeyExpansion_t, Block_t> tester{
    byteInterface,
    callbacks
};

int main(){
    // (Optional but recommended) Validate memory management first
    std::cout << "\nValidating memory management callbacks..." << std::endl;
    if (!tester.validateInfrastructure()) {
        std::cerr << "Fix allocation/deallocation and byte interface functions before proceeding." << std::endl;
        return 1;
    }
    std::cout << "Infrastructure validated successfully.\n" << std::endl;

    // Define crypto functions to test
    auto keyExpansionBuilder = []( const unsigned char* key, size_t keySize, KeyExpansion_t* ke) -> int {
        // Your key expansion implementation
        return KeyExpansionInit(ke, key, keySize, false);
    };

    auto encryptor = [](const Block_t*const input, const KeyExpansion_t*const ke, Block_t* output) -> int {
        return encryptBlock(input, ke, output, false);  // debugHard = false
    };

    auto decryptor = [](const Block_t*const input, const KeyExpansion_t*const ke, Block_t* output) -> int {
        return decryptBlock(input, ke, output, false);
    };

    // Run full test suite for all key sizes
    bool allTestsPass = true;

    allTestsPass &= tester.runTestSuite(
        TestVectors::AES::KeySize::AES128,
        keyExpansionBuilder, encryptor, decryptor
    );

    allTestsPass &= tester.runTestSuite(
        TestVectors::AES::KeySize::AES192,
        keyExpansionBuilder, encryptor, decryptor
    );

    allTestsPass &= tester.runTestSuite(
        TestVectors::AES::KeySize::AES256,
        keyExpansionBuilder, encryptor, decryptor
    );

    // Print final results
    if (allTestsPass) {
        std::cout << "\n========================================" << std::endl;
        std::cout << "✓ ALL TESTS PASSED" << std::endl;
        std::cout << "========================================" << std::endl;
        return 0;
    } else {
        std::cout << "\n========================================" << std::endl;
        std::cout << "✗ SOME TESTS FAILED" << std::endl;
        std::cout << "========================================" << std::endl;
        return 1;
    }
    return 0;
}
