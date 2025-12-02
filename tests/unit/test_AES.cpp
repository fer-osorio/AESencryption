#include "../include/test-encryption/test_encryption_c.hpp"
#include "../../data-encryption/include/AES.h"

static ptrKeyExpansion_t (*allocateKeyExapansion)(size_t) = KeyExpansionMemoryAllocationZero;
static void              (*freeKeyExpansion)(KeyExpansion_t**) = KeyExpansionDelete;
static ptrBlock_t        (*allocateBlock)() = BlockMemoryAllocationZero;
static void              (*freeBlock)(Block_t**) = BlockDelete;

MemoryCallbacks<KeyExpansion_t, Block_t> callbacks{
    allocateKeyExapansion,
    freeKeyExpansion,
    allocateBlock,
    freeBlock
};

static bool (*compareKeyExpansionBytes_)(const KeyExpansion_t*const input, const uint8_t* bytes) = compareKeyExpansionBytes;
static bool (*compareBlockBytes_)(const Block_t*const input, const uint8_t* bytes) = compareBlockBytes;

EncryptionTester<KeyExpansion_t, Block_t> tester{
    compareKeyExpansionBytes_,
    [](KeyExpansion_t*const output, size_t keylenbits, const unsigned char*const input) -> int{
        return static_cast<int>(KeyExpansionFromBytes(output, keylenbits, input));
    },
    compareBlockBytes_,
    [](Block_t*const output, const unsigned char*const input) -> int {
        return static_cast<int>(BlockWriteFromBytes(output, input));
    },
    callbacks
};

int main(){
    // (Optional but recommended) Validate memory management first
    std::cout << "\nValidating memory management callbacks..." << std::endl;
    if (!tester.validateMemoryCallbacks()) {
        std::cerr << "\nERROR: Memory callbacks are broken!" << std::endl;
        std::cerr << "Fix allocation/deallocation functions before proceeding." << std::endl;
        return 1;
    }
    std::cout << "Memory callbacks validated successfully.\n" << std::endl;

    // Define crypto functions to test
    auto keyExpansionBuilder = [](
        const unsigned char* key,
        size_t keySize,
        ptrKeyExpansion_t ke
    ) -> int {
        // Your key expansion implementation
        return KeyExpansionBuild(ke, key, keySize, false);
    };

    auto encryptor = [](
        const Block_t*const input,
        const KeyExpansion_t*const ke,
        Block_t* output
    ) -> int {
        return encryptBlock(input, ke, output, false);  // debugHard = false
    };

    auto decryptor = [](
        const Block_t*const input,
        const KeyExpansion_t*const ke,
        Block_t* output
    ) -> int {
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
