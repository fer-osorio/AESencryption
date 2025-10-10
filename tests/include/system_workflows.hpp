#include "test_framework.hpp"
#include <filesystem>
#include <fstream>

namespace CommandLineToolsTest{

enum struct FileFormat {
	UNKNOWN,
	BINARY,		// Binary files
	TEXT,		// Text files
	BITMAP		// Bitmap images
};

namespace SystemUtils {
	// Helper function to execute command line tool
	int execute_cli_command(const std::string& command);

	// Helper to create text files
	void create_text_file(const std::string& filepath, const std::string& content);

	// Helper to create binary files
	void create_binary_file(const std::string& filepath, const std::vector<uint8_t>& content);

	// Helper to create binary files
	void create_binary_file(const std::string& filepath, std::function<uint8_t(size_t)> generator, size_t file_size);

	// Helper to read file content
	std::vector<uint8_t> read_file(const std::string& filepath, bool isBinary);

	// Return a string representing an associated extension to the input file format
	std::string toFileExtension(FileFormat ff);
} // namespace SystemTestUtil

namespace fs = std::filesystem;

class SystemTests {
private:
	const std::string executable_path;
	const FileFormat ff_;

	// Test file paths
	const fs::path testDataDir = "test_data";
	fs::path originalValidPath = testDataDir / "original_valid";
	fs::path originalLargePath = testDataDir / "original_large";
	fs::path nonexistentPath = testDataDir / "does_not_exist";
	fs::path encryptedOriginalValidPath = testDataDir / "encrypted_original_valid";
	fs::path decryptedOriginalValidPath = testDataDir / "decrypted_original_valid";
	fs::path encryptedOriginalLargePath = testDataDir / "encrypted_original_large";
	fs::path decryptedOriginalLargePath = testDataDir / "decrypted_original_large";
	const fs::path keyPath = testDataDir / "key.bin";

	void setupTestEnvironment(FileFormat ff);
	void cleanupTestEnvironment();

public:
	SystemTests(const std::string executable_path_, FileFormat ff);
	~SystemTests();

	// SYSTEM TEST 1: Complete Text File Encryption Workflow
	bool test_text_file_encryption_workflow();

	// SYSTEM TEST 2: Error Handling and Edge Cases
	bool test_error_scenarios();

	// SYSTEM TEST 3: Performance and Large File Handling
	bool test_large_file_performance();
}; // class SystemTests

} // namespace CommandLineToolsTest