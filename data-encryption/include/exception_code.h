#ifndef EXCEPTION_CODE
#define EXCEPTION_CODE

#ifdef __cplusplus
extern "C" {
#endif

enum ExceptionCode{
  NoException,
  NullKey, NullKeyExpansion, NullSource, NullDestination, NullInput, NullOutput, NullInitialVector,
  ZeroLength, InvalidKeyLength, InvalidInputSize,
  UnknownOperation
};

#ifdef __cplusplus
}
#endif

#endif
