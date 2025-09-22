#ifndef PRINT_BYTES_HPP
#define PRINT_BYTES_HPP

#include<iostream>
#include<iomanip>

// A safe, stream-based helper to print a range of bytes as hexadecimal.
template<typename T> void print_bytes_as_hex(std::ostream& os, const T* data, size_t size) {
    if (!data) return;
    // Save current stream flags
    std::ios_base::fmtflags f(os.flags());
    os << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        os << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    // Restore original stream flags
    os.flags(f);
}

#endif