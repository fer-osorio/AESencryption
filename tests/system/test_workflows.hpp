#include "../include/test_framework.hpp"
#include <filesystem>
#include <fstream>

namespace SystemTestUtils {
	// Helper function to execute command line tool
	int execute_cli_command(const std::string& command);

	// Helper to create test files
	void create_test_file(const std::string& filename, const std::string& content);

	// Helper to read file content
	std::string read_file_content(const std::string& filename);

	// Helper to create test bitmap
	void create_test_bitmap(const std::string& filename, size_t width, size_t height);
} // namespace SystemTestUtils

namespace commandLineTools_test{
	// SYSTEM TEST 1: Complete Text File Encryption Workflow
	void test_text_file_encryption_workflow();

	// SYSTEM TEST 2: Image File Encryption Workflow
	void test_image_encryption_workflow();

	// SYSTEM TEST 3: Error Handling and Edge Cases
	void test_error_scenarios();

	// SYSTEM TEST 4: Performance and Large File Handling
	void test_large_file_performance();
}