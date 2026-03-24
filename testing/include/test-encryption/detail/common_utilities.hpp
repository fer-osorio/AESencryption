#ifndef CRYPTO_TEST_DETAIL_COMMON_UTILITIES_HPP
#define CRYPTO_TEST_DETAIL_COMMON_UTILITIES_HPP

namespace CryptoTest {
    namespace Common {

        /**
         * @brief Standard error codes for crypto operations
         */
        enum class ErrorCode {
            SUCCESS = 0,
            NULL_POINTER = -1,
            INVALID_KEY_SIZE = -2,
            INVALID_PARAMETER = -3,
            OPERATION_FAILED = -4
        };

        /**
         * @brief Convert error code to string
         */
        inline const char* errorCodeToString(ErrorCode code) {
            switch (code) {
                case ErrorCode::SUCCESS: return "Success";
                case ErrorCode::NULL_POINTER: return "Null pointer";
                case ErrorCode::INVALID_KEY_SIZE: return "Invalid key size";
                case ErrorCode::INVALID_PARAMETER: return "Invalid parameter";
                case ErrorCode::OPERATION_FAILED: return "Operation failed";
                default: return "Unknown error";
            }
        }

    } // namespace Common
} // namespace CryptoTest

#endif // CRYPTO_TEST_DETAIL_COMMON_UTILITIES_HPP
