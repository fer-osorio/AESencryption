/**
 * @file test_vectors.hpp
 * @brief Unified header for AES Test Vectors Library
 *
 * This is the main entry point for the TestVectors library.
 * Include this single header to access all NIST test vectors
 * for AES (FIPS 197 and SP 800-38A).
 *
 * @example
 * #include "test_vectors.hpp"
 *
 * auto vec = TestVectors::AES::FIPS197::Cipher::create(
 *     TestVectors::AES::KeySize::AES128
 * );
 */

#ifndef TEST_VECTORS_HPP
#define TEST_VECTORS_HPP

// Core definitions (always needed)
#include "common.hpp"
#include "keys.hpp"

// FIPS 197 test vectors
#include "fips197_key_expansion.hpp"
#include "fips197_cipher.hpp"

// SP 800-38A mode test vectors
#include "sp800_38a_modes.hpp"

// Stub/mock data (optional - you might make this separate)
#include "stub_data.hpp"

#endif // TEST_VECTORS_HPP
