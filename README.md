# CipherFortis

A modular C/C++ library for file encryption using AES (Advanced Encryption Standard) with built-in encryption quality analysis through statistical metrics.

## Features

- **AES encryption** supporting 128, 192, and 256-bit keys
- **Multiple operation modes**: ECB, CBC, OFB, CTR
- **File format support**: BMP images, PNG, JPEG, text files, generic binary files
- **Encryption quality metrics**: Entropy, Chi-Square, correlation analysis
- **NIST-compliant implementation** with comprehensive test vectors
- **HSM integration** via PKCS#11 for hardware-backed key management
- **Modular architecture** for easy extension to new file formats
- **Command-line tools** for immediate use

## Quick Start

### Building the Project

```bash
# Clone the repository
git clone <repository-url>
cd CipherFortis

# Build all components (requires GCC/G++ and Make)
make

# Build specific components
make core-aes        # Core AES implementation (C)
make core            # C++ wrapper classes
make tests           # Test suite

# Run tests
cd tests
make run-all
```

### Encrypting Your First File

```bash
# Generate a 256-bit key
./bin/command-line-tools/image-encryption/image_encryptor \
    --generate-key --key-length 256 --output my_key.bin

# Encrypt an image (CBC mode)
./bin/command-line-tools/image-encryption/image_encryptor \
    --encrypt \
    --key my_key.bin \
    --input photo.png \
    --output encrypted.png \
    --mode CBC

# Decrypt the image
./bin/command-line-tools/image-encryption/image_encryptor \
    --decrypt \
    --key my_key.bin \
    --input encrypted.png \
    --output decrypted.png \
    --mode-data <mode_data_file>
```

### Using as a Library

```cpp
#include "cipher.hpp"

// Create a cipher with 256-bit key and CBC mode
CipherFortis::Cipher cipher(
    CipherFortis::Key::LengthBits::_256,
    CipherFortis::Cipher::OperationMode::Identifier::CBC
);

// Load and encrypt a file
File::RasterImage image("input.png");
image.load();
image.apply_encryption(cipher);
image.save("encrypted.png");

// Analyze encryption quality
DataRandomness metrics = image.calculate_randomness();
std::cout << "Entropy: " << metrics.getEntropy() << std::endl;
```

## Project Structure

```
CipherFortis/
├── core-crypto/
│   ├── aes/              # Core AES implementation (C): ECB, CBC, OFB, CTR
│   ├── include/          # Public C++ API: Cipher, Key, Encryptor
│   └── src/              # C++ wrapper implementation
├── file-handlers/        # File format support (BMP, PNG, JPEG, text, binary)
├── analysis/             # Statistical encryption quality analysis
├── cli-tools/            # CLI configuration and argument parsing
├── hsm-integration/      # PKCS#11 HSM adapter
├── command-line-tools/   # Ready-to-use encryption tools
├── testing/              # NIST test vectors and test framework
├── tests/                # Test suite
│   ├── unit/             # Unit tests
│   ├── integration/      # Integration tests
│   └── system/           # End-to-end workflow tests
└── lib/                  # Compiled static libraries (generated)
```

## Build System

The project uses a hierarchical Makefile system:

- **`config.mk`**: Compiler settings, optimization levels, build types
- **`common.mk`**: Shared functions and utilities
- **Module Makefiles**: Each module has its own Makefile

### Build Types

```bash
make BUILD_TYPE=debug     # Debug build with sanitizers (default)
make BUILD_TYPE=release   # Optimized release build
make BUILD_TYPE=test      # Test build with coverage analysis
make BUILD_TYPE=profile   # Profiling build
```

### Build Targets

```bash
make all                 # Build everything
make clean               # Clean all build artifacts
make core-aes            # Build only core AES (C library)
make core                # Build C++ wrapper
make file-handlers       # Build file format handlers
make tests               # Build test suite
make command-line-tools  # Build CLI tools
```

## Documentation (coming soon)

- **[Architecture Overview](docs/ARCHITECTURE.md)** - System design and module interactions
- **[Building Guide](docs/BUILDING.md)** - Detailed build instructions and troubleshooting
- **[Library Usage](docs/USAGE_LIBRARY.md)** - Integrating the library into your project
- **[Framework Guide](docs/USAGE_FRAMEWORK.md)** - Extending with new file formats
- **[Encryption Quality Metrics](docs/ENCRYPTION_QUALITY.md)** - Understanding statistical analysis
- **[Testing Strategy](docs/TESTING.md)** - Test suite organization and NIST compliance
- **[API Reference](docs/api/)** - Generated API documentation (Doxygen)

## Requirements

### Build Requirements

- **Compiler**: GCC 7+ or Clang 6+ (C11 and C++17 support)
- **Build tools**: GNU Make 4.0+
- **Platform**: Linux (primary), macOS and Windows support in progress

#### Debug Build Dependencies (default)
The default `BUILD_TYPE=debug` enables memory sanitizers which require additional runtime libraries:

**Debian/Ubuntu:**
```bash
sudo apt-get install libasan6 libubsan1 liblsan0
```

**Fedora/RHEL:**
```bash
sudo dnf install libasan libubsan liblsan
```

**Arch Linux:**
```bash
# Included with gcc package
```

**Alternative:** Build without sanitizers:
```bash
make BUILD_TYPE=release  # No sanitizer dependencies needed
```

### Optional Tools

- **Valgrind** (for memory testing)
- **lcov** (for coverage reports)

## Platform Support

| Platform | Status            | Notes                          |
| -------- | ----------------- | ------------------------------ |
| Linux    | ✅ Fully supported | Primary development platform   |
| macOS    | 🟡 In progress    | Basic functionality working    |
| Windows  | 🟡 Planned        | MinGW/MSYS2 or WSL recommended |

## Installation

This project is currently designed for **local use** rather than system-wide installation:

1. Build the project in place: `make`
2. Use binaries from `./bin/` directory
3. Link against libraries in `./lib/` directory

For integration into other projects:

```bash
# Add to your project's include path
-I/path/to/CipherFortis/core-crypto/include
-I/path/to/CipherFortis/core-crypto/aes/include
-I/path/to/CipherFortis/file-handlers/include

# Link against libraries
-L/path/to/CipherFortis/lib -lciphfortis_core -lciphfortis_aes -lciphfortis_files
```

## Testing

The project includes extensive testing with NIST test vectors:

```bash
cd tests
make dependencies      # Build required libraries
make all               # Build all tests
make run-all           # Run all test suites

# Run specific test categories
make run-unit
make run-integration
make run-system
```

Test coverage includes:

- ✅ NIST FIPS 197 test vectors (key expansion, encryption/decryption)
- ✅ NIST SP 800-38A test vectors (ECB, CBC, OFB, CTR modes)
- ✅ File format handling edge cases
- ✅ End-to-end encryption workflows

## Roadmap

### Current Focus

- [ ] Complete cross-platform support (macOS, Windows)
- [ ] Performance optimizations

### Future Goals

- [ ] System-wide installation support
- [ ] Python bindings
- [ ] GUI application
- [ ] Hardware acceleration (AES-NI)

## Contributing

This project is currently in early development. Contributions, suggestions, and bug reports are welcome!

### Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and test thoroughly
4. Commit with clear messages following Angular convention (see `docs/angular_commit_convention.md`)
5. Push to your fork: `git push origin feature/amazing-feature`
6. Open a Pull Request

### Development Guidelines

- Add tests for new functionality
- Update documentation for API changes
- Ensure `make run-all` passes in the tests directory

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

- AES algorithm implementation follows NIST FIPS 197 specification
- Test vectors derived from NIST Special Publication 800-38A
- Inspired by the need for transparent, analyzable encryption implementations

## Contact

Mail me at aosorios1502@alumno.ipn.mx and alexis.fernando.osorio.sarabio@gmail.com for questions and comments.

---

**Status**: This project is under active development. APIs may change as the project evolves toward a stable 1.0 release.
