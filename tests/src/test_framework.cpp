#include"../include/test_framework.hpp"
#include<cstring>

#define TF_COLOR_RED    "\033[31m"
#define TF_COLOR_GREEN  "\033[32m"
#define TF_COLOR_BLUE   "\033[34m"
#define TF_COLOR_NC     "\033[0m"   // No color
#define TF_INFO         "\t\033[34m[INFO]\033[0m"
#define TF_SUCCESS      "\t\033[32m[SUCCESS]\033[0m"
#define TF_FAILURE      "\t\033[31m[FAILURE]\033[0m"

using namespace TestFramework;

TestSuite::TestSuite(const std::string& name) : suiteName(name) {}

static std::ostream& sendSuccessMessage(std::ostream& os, const std::string& testName){
    os << TF_COLOR_GREEN "  ✓ " << testName << TF_COLOR_NC << std::endl;
    return os;
}

static std::ostream& sendFailureMessage(std::ostream& os, const std::string& testName){
    os << TF_COLOR_RED "  ✗ " << testName << " - FAILED" TF_COLOR_NC << std::endl;
    return os;
}

bool TestSuite::assertTrue(bool condition, const std::string& testName){
    this->testsRun++;
    if(condition) {
        this->testsPassed++;
        sendSuccessMessage(std::cout, testName);
    } else {
        this->failedTests.push_back(testName);
        sendFailureMessage(std::cout, testName);
    }
    return condition;
}

bool TestSuite::assertEqual(int expected, int actual, const std::string& testName){
    this->testsRun++;
    if(expected == actual) {
        this->testsPassed++;
        sendSuccessMessage(std::cout, testName);
        return true;
    } else {
        this->failedTests.push_back(testName + " (expected: " + std::to_string(expected) + ", got: " + std::to_string(actual) + ")");
        sendFailureMessage(std::cout, testName) << TF_INFO"(expected: " << expected << ", got: " << actual << ")" << std::endl;
        return false;
    }
}

bool TestSuite::assertBytesEqual(const uint8_t* expected, const uint8_t* actual, size_t len, const std::string& testName){
    this->testsRun++;
    if(memcmp(expected, actual, len) == 0) {
        this->testsPassed++;
        sendSuccessMessage(std::cout, testName);
        return true;
    } else {
        this->failedTests.push_back(testName + " (byte arrays differ)");
        sendFailureMessage(std::cout, testName) << TF_INFO"(byte arrays differ)" << std::endl;
        // Show first differing bytes for debugging
        for(size_t i = 0; i < len; i++) {
            if(expected[i] != actual[i]) {
                std::cout << "\tFirst difference at byte number" << i
                          << ": expected 0x" << std::hex << static_cast<int>(expected[i])
                          << ", got 0x" << static_cast<int>(actual[i]) << std::dec << std::endl;
                break;
            }
        }
        return false;
    }
}

bool TestSuite::assertNotNull(const void* ptr, const std::string& testName){
    this->testsRun++;
    if(ptr != NULL) {
        this->testsPassed++;
        sendSuccessMessage(std::cout, testName);
        return true;
    } else {
        this->failedTests.push_back(testName + " (pointer is null)");
        sendFailureMessage(std::cout, testName) << TF_INFO"(pointer is null)" << std::endl;
        return false;
    }
}

template<typename ExceptionType>
bool TestSuite::assertThrows(std::function<void()> func, const std::string& testName) {
    testsRun++;
    try {
        func();  // Execute the function
        // If we reach here, no exception was thrown - test fails
        std::cout << "  ✗ FAILED: " << testName
                  << " (Expected exception not thrown)" << std::endl;
        failedTests.push_back(testName);
        return false;
    }
    catch (const ExceptionType& e) {
        // Correct exception type was thrown - test passes
        testsPassed++;
        std::cout << "  ✓ PASSED: " << testName
                  << " (Caught expected exception: " << e.what() << ")" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        // Wrong exception type was thrown - test fails
        std::cout << "  ✗ FAILED: " << testName
                  << " (Wrong exception type: " << e.what() << ")" << std::endl;
        failedTests.push_back(testName);
        return false;
    }
    catch (...) {
        // Unknown exception type - test fails
        std::cout << "  ✗ FAILED: " << testName
                  << " (Unknown exception type)" << std::endl;
        failedTests.push_back(testName);
        return false;
    }
}

// Overload for any exception (not type-specific)
bool TestSuite::assertThrows(std::function<void()> func, const std::string& testName) {
    testsRun++;
    try {
        func();
        std::cout << "  ✗ FAILED: " << testName
                  << " (Expected exception not thrown)" << std::endl;
        failedTests.push_back(testName);
        return false;
    }
    catch (...) {
        testsPassed++;
        std::cout << "  ✓ PASSED: " << testName
                  << " (Exception thrown as expected)" << std::endl;
        return true;
    }
}

bool TestSuite::runTest(std::function<bool ()> testFunc, const std::string& testName){
    bool success = false;
    this->testsRun++;
    try {
        success = testFunc();
    } catch(const std::exception& exp) {
        this->failedTests.push_back(testName + " (exception: " + exp.what() + ")");
        sendFailureMessage(std::cout, testName) << TF_INFO"(exception: " << exp.what() << ")" << std::endl;
    }
    if(success == true) {
        this->testsPassed++;
        sendSuccessMessage(std::cout, testName);
        return true;
    } else {
        this->failedTests.push_back(testName + " (function exit with non success status)");
        sendFailureMessage(std::cout, testName) << TF_INFO"(function exit with non success status)" << std::endl;
        return false;
    }
}

void TestSuite::printResults(){
    std::cout << "\n" << std::string(65, '=') << "\n";
    std::cout << TF_INFO " Test Suite: " << this->suiteName << "\n";
    std::cout << TF_INFO " Tests run: " << this->testsRun << "\n";
    std::cout << TF_INFO " Tests passed: " << this->testsPassed << "\n";
    std::cout << TF_INFO " Tests failed: " << (this->testsRun - this->testsPassed) << "\n";

    if(this->testsPassed == this->testsRun) {
        std::cout << TF_SUCCESS TF_COLOR_GREEN" ✓ ALL TESTS PASSED" TF_COLOR_NC << "\n";
    } else {
        std::cout << TF_FAILURE TF_COLOR_RED" ✗ SOME TESTS FAILED:" TF_COLOR_NC << "\n";
        for (const std::string& failure : this->failedTests) {
            std::cout << "  - " << failure << "\n";
        }
    }
    std::cout << std::string(65, '=') << std::endl;
}

bool TestSuite::allPassed() const{
    return this->testsPassed == testsRun;
}

int TestSuite::getFailedCount() const {
    return this->testsRun - this->testsPassed;
}
