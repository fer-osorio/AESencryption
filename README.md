# AESencryption

A modular C/C++ library for AES-based file encryption with integrated statistical quality analysis.

## Overview

AESencryption provides both a robust encryption library and a framework for building file-encryption applications. What sets it apart is its built-in capability to measure encryption quality through statistical methods, ensuring your encrypted data exhibits proper randomness characteristics.

**Key Features:**
- AES encryption (128/192/256-bit keys) with ECB and CBC modes
- File format handlers (BMP, text, extensible to others)
- Statistical analysis of encryption quality
- C library core with C++ wrapper classes
- Command-line tools for immediate use

## Quick Start

### Building the Project

```bash
# Clone the repository
git clone <repository-url>
cd AESencryption

# Build all components
make

# Build specific components
make data-encryption  # Core AES implementation (C)
make core            # C++ wrapper classes
make file-handlers   # File format support
make tests           # Test suite
```

**Requirements:**
- GCC or Clang with C11/C++17 support
- GNU Make
- Linux (primary), cross-platform support in progress

### Encrypting Your First File

```bash
# Using the command-line tool (after building)
bin/command-line-tools/image-encryption/bmp_encryptor --encrypt --key <keyfile> --input <file> --output <file>

# If the key file it doesn't exist, an exception is thrown asking to create a key first
```

### Using as a Library (C++)

```cpp
#include "cipher.hpp"  // key.hpp and encryptor.hpp files are already included in cipher.hpp

using namespace AESencryption;

// Create a 256-bit key
Key key(Key::LengthBits::_256);

// Create cipher with CBC mode
Cipher cipher(key, Cipher::OperationMode::Identifier::CBC);

// Encrypt data
std::vector<uint8_t> plaintext = /* your data */;
std::vector<uint8_t> ciphertext(plaintext.size());
cipher.encryption(plaintext, ciphertext);

// Save key for later use
key.save("mykey.bin");
```

## Project Structure

```
AESencryption/
├── data-encryption/    # Core AES implementation (C)
├── src/core/          # C++ wrapper classes (Key, Cipher)
├── file-handlers/     # File format support (BMP, text)
├── metrics-analysis/  # Statistical quality measurement
├── CLI/               # Command-line interface utilities
├── command-line-tools/# Ready-to-use encryption tools
├── tests/             # Unit, integration, and system tests
├── include/           # Public API headers
├── lib/               # Generated static libraries
└── bin/               # Generated executables
```

**Module Dependencies:**
```
command-line-tools → file-handlers → core → data-encryption
                                   ↘ metrics-analysis
tests → all modules
```

## Architecture Highlights

### Modular Design
- **C core** (`data-encryption`): Pure AES implementation, no dependencies
- **C++ wrapper** (`src/core`): Object-oriented interface with RAII guarantees
- **Extensibility**: Implement `Encryptor` interface to support new encryption schemes
- **File handlers**: Abstract `FileBase` class for format-specific encryption

### Encryption Quality Analysis
The `metrics-analysis` module measures randomness properties of encrypted data:
- Chi-square goodness-of-fit test
- Entropy calculations
- Data correlation

This helps verify that your encryption produces properly randomized output.

## Documentation

- **[Building](docs/BUILDING.md)** - Detailed build instructions and troubleshooting *(coming soon)*
- **[Architecture](docs/ARCHITECTURE.md)** - System design and module interactions *(coming soon)*
- **[API Reference](docs/api/)** - Detailed API documentation *(coming soon)*
- **[Testing](docs/TESTING.md)** - Test strategy and execution *(coming soon)*

### Module Documentation
*(coming soon)*

## Testing

```bash
# Build and run all tests
make tests
cd tests
make run-all

# Run specific test categories
make run-unit
make run-integration
make run-system
```

The test suite includes:
- **Unit tests**: Individual component validation
- **Integration tests**: Module interaction verification
- **System tests**: End-to-end workflow testing
- **NIST test vectors**: Compliance with FIPS 197 and SP 800-38A standards

## Current Status

**Stable:**
- ✅ AES-128/192/256 encryption and decryption
- ✅ ECB and CBC operation modes
- ✅ BMP file encryption
- ✅ Comprehensive test coverage with NIST vectors

**In Progress:**
- 🚧 Cross-platform support (Windows, macOS)
- 🚧 Documentation completion
- 🚧 Additional file format handlers

**Planned:**
- 📋 Additional operation modes (CTR, GCM)

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux    | ✅ Full | Primary development platform |
| macOS    | 🚧 Experimental | Cross-compilation support in progress |
| Windows  | 🚧 Experimental | Cross-compilation support in progress |

## Examples

### Encrypting a Bitmap Image

```bash
Generate 192-bits key
bin/command-line-tools/image-encryption/bmp_encryptor --generate-key --key-length 192 --output key.bin

# Encrypt
bin/command-line-tools/image-encryption/bmp_encryptor --encrypt --key key.bin --input photo.bmp --output encrypted.bmp

# Decrypt
bin/command-line-tools/image-encryption/bmp_encryptor --decrypt --key key.bin --input encrypted.bmp --output decrypted.bmp

# Verify they match
diff photo.bmp decrypted.bmp
```

### Custom Cipher Configuration

```cpp
#include "cipher.hpp"
#include "key.hpp"
#include <vector>

using namespace AESencryption;

// Build 128-bits key automatically
Key key(Key::LengthBits:::_128);

// Create cipher with specific operation mode
Cipher cipher(key, Cipher::OperationMode::Identifier::CBC);

// Use cipher for encryption
std::vector<uint8_t> data = /* ... */;
std::vector<uint8_t> encrypted(data.size());
cipher.encryption(data, encrypted);
```

## Contributing

This project is currently in active development. Contributions, suggestions, and feedback are welcome! As the project matures, formal contribution guidelines will be established.

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

- AES algorithm implementation follows NIST FIPS 197 specification
- Test vectors derived from NIST Special Publication 800-38A
- Inspired by the need for transparent, analyzable encryption implementations

---

**Note:** This project is under active development. APIs may change as the project evolves toward a stable 1.0 release. For questions or issues, please open an issue on the repository.
