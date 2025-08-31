#ifndef TEST_FRAMEWORK_HPP
#define TEST_FRAMEWORK_HPP

#include<iostream>
#include<vector>
#include<cstdint>
#include<functional>

namespace TestFramework{
class TestSuite{
private:
	std::string suiteName;
	int testsRun = 0;
	int testsPassed = 0;
	std::vector<std::string> failedTests;
public:
	TestSuite(const std::string& name);

	// Test assertion macros
	void assertTrue(bool condition, const std::string& testName);
	void assertEqual(int expected, int actual, const std::string& testName);
	void assertBytesEqual(const uint8_t* expected, const uint8_t* actual, size_t len, const std::string& testName);
	void assertNotNull(const void* ptr, const std::string& testName);

	// Run a test function and catch exceptions
	void runTest(std::function<bool ()> testFunc, const std::string& testName);

	// Print final results
	void printResults();

	bool allPassed() const;
	int getFailedCount() const;
};

// Utility macros for cleaner test writing
#define TEST_SUITE(name) TestFramework::TestSuite suite("name"); std::cout << "Running " << "name" << "..." << std::endl;
#define ASSERT_TRUE(condition, name) suite.assert_true(condition, name)
#define ASSERT_EQUAL(expected, actual, name) suite.assert_equal(expected, actual, name)
#define ASSERT_BYTES_EQUAL(expected, actual, len, name) suite.assert_bytes_equal(expected, actual, len, name)
#define ASSERT_NOT_NULL(ptr, name) suite.assert_not_null(ptr, name)
#define RUN_TEST(func, name) suite.run_test(func, name)
#define PRINT_RESULTS() suite.print_results()
#define SUITE_PASSED() suite.all_passed()

}

#endif