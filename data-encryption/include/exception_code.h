/**
 * @file exception_code.h
 * @brief Exception codes for AES encryption/decryption operations
 *
 * This file defines the ExceptionCode enumeration used to report
 * the status of cryptographic operations. All functions return
 * these codes to indicate success or the specific type of error
 * that occurred.
 *
 * @note NoException (value 0) indicates successful operation
 */

#ifndef EXCEPTION_CODE_H
#define EXCEPTION_CODE_H

#ifdef __cplusplus
extern "C" {
#endif

/**
  * @enum ExceptionCode
  * @brief Status codes returned by encryption and decryption functions
  *
  * This enumeration defines all possible return codes for the AES
  * encryption and decryption operations. A return value of NoException
  * indicates successful completion, while any other value indicates
  * a specific error condition.
  */
enum ExceptionCode {
  /** @brief Operation completed successfully */
  NoException,

  /* Null pointer errors */

  /** @brief The key pointer is NULL */
  NullKey,

  /** @brief The key expansion pointer is NULL */
  NullKeyExpansion,

  /** @brief The source pointer is NULL (deprecated, use NullInput) */
  NullSource,

  /** @brief The destination pointer is NULL (deprecated, use NullOutput) */
  NullDestination,

  /** @brief The input data pointer is NULL */
  NullInput,

  /** @brief The output data pointer is NULL */
  NullOutput,

  /** @brief The initialization vector (IV) pointer is NULL */
  NullInitialVector,

  /* Size and parameter validation errors */

  /** @brief The size parameter is zero */
  ZeroLength,

  /** @brief The key length is invalid (must be 128, 192, or 256 bits) */
  InvalidKeyLength,

  /** @brief The input size is invalid (must be at least 16 bytes, other restriction may apply for specific
   *operation modes) */
  InvalidInputSize,

  /* Operation errors */

  /** @brief The requested operation is not recognized or supported */
  UnknownOperation
};

#ifdef __cplusplus
}
#endif

#endif
