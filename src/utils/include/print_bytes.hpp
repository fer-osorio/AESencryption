#ifndef PRINT_BYTES_HPP
#define PRINT_BYTES_HPP

#include<iostream>

// A safe, stream-based helper to print a range of bytes as hexadecimal.
template<typename T> void print_bytes_as_hex(std::ostream& os, const T* data, size_t size);

#endif