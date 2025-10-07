#include "test_framework.hpp"
#include <filesystem>
#include <fstream>

namespace CommandLineToolsTest{

namespace SystemUtils {
	// Helper function to execute command line tool
	int execute_cli_command(const std::string& command);

	// Helper to create test files
	void create_test_file(const std::string& filename, const std::string& content);

	// Helper to read file content
	std::string read_file_content(const std::string& filename);

	// Helper to create test bitmap
	void create_test_bitmap(const std::string& filename, size_t width, size_t height);
} // namespace SystemTestUtil

namespace fs = std::filesystem;

class SystemTests {
private:
	const std::string executable_path;

	// Test file paths
	const fs::path testDataDir = "test_data";
	const fs::path validPath = testDataDir / "valid";
	const fs::path smallPath = testDataDir / "small";
	const fs::path largePath = testDataDir / "large";
	const fs::path nonexistentPath = testDataDir / "does_not_exist";

	// SYSTEM TEST 1: Complete Text File Encryption Workflow
	static bool test_text_file_encryption_workflow();

	// SYSTEM TEST 2: Image File Encryption Workflow
	static bool test_image_encryption_workflow();

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