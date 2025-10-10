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

	// Test file paths
	const fs::path testDataDir = "test_data";
	fs::path validPath = testDataDir / "valid";
	fs::path largePath = testDataDir / "large";
	fs::path nonexistentPath = testDataDir / "does_not_exist";
	fs::path encryptedPath = testDataDir / "encrypted";
	fs::path decryptedPath = testDataDir / "decrypted";
	fs::path keyPath = testDataDir / "key.bin";

	void setupTestEnvironment(FileFormat ff);
	void cleanupTestEnvironment();

	// SYSTEM TEST 1: Complete Text File Encryption Workflow
	bool test_text_file_encryption_workflow(FileFormat);

	// SYSTEM TEST 2: Image File Encryption Workflow
	bool test_image_encryption_workflow();

	// SYSTEM TEST 3: Error Handling and Edge Cases
	bool test_error_scenarios();

	// SYSTEM TEST 4: Performance and Large File Handling
	bool test_large_file_performance();
public:
	// SYSTEM TEST 1: Complete Text File Encryption Workflow
	static SystemTests test_text_file_encryption();

	// SYSTEM TEST 2: Image File Encryption Workflow
	static SystemTests test_image_encryption();
}; // class SystemTests

} // namespace CommandLineToolsTest