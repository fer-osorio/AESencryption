#include"../include/test_framework.hpp"
#include<cstring>

using namespace TestFramework;

TestSuite::TestSuite(const std::string& name) : suiteName(name) {}

bool TestSuite::assertTrue(bool condition, const std::string& testName){
    this->testsRun++;
    if(condition) {
        this->testsPassed++;
        std::cout << "  ✓ " << testName << std::endl;
    } else {
        this->failedTests.push_back(testName);
        std::cout << "  ✗ " << testName << " - FAILED" << std::endl;
    }
    return condition;
}

bool TestSuite::assertEqual(int expected, int actual, const std::string& testName){
    this->testsRun++;
    if(expected == actual) {
        this->testsPassed++;
        std::cout << "  ✓ " << testName << std::endl;
        return true;
    } else {
        this->failedTests.push_back(testName + " (expected: " + std::to_string(expected) + ", got: " + std::to_string(actual) + ")");
        std::cout << "  ✗ " << testName << " - FAILED (expected: " << expected << ", got: " << actual << ")" << std::endl;
        return false;
    }
}

bool TestSuite::assertBytesEqual(const uint8_t* expected, const uint8_t* actual, size_t len, const std::string& testName){
    this->testsRun++;
    if(memcmp(expected, actual, len) == 0) {
        this->testsPassed++;
        std::cout << "  ✓ " << testName << std::endl;
        return true;
    } else {
        this->failedTests.push_back(testName + " (byte arrays differ)");
        std::cout << "  ✗ " << testName << " - FAILED (byte arrays differ)" << std::endl;
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
    if(ptr != nullptr) {
        this->testsPassed++;
        std::cout << "  ✓ " << testName << std::endl;
        return true;
    } else {
        this->failedTests.push_back(testName + " (pointer is null)");
        std::cout << "  ✗ " << testName << " - FAILED (pointer is null)" << std::endl;
        return false;
    }
}

bool TestSuite::runTest(std::function<bool ()> testFunc, const std::string& testName){
    bool success = false;
    this->testsRun++;
    try {
        success = testFunc();
    } catch(const std::exception& exp) {
        this->failedTests.push_back(testName + " (exception: " + exp.what() + ")");
        std::cout << "  ✗ " << testName << " - FAILED (exception: "
                  << exp.what() << ")" << std::endl;
    }
    if(success == true) {
        this->testsPassed++;
        std::cout << "  ✓ " << testName << std::endl;
        return true;
    } else {
        this->failedTests.push_back(testName + " (function exit with non success status)");
        std::cout << "  ✗ " << testName << " - FAILED (function exit with non success status)" << std::endl;
        return false;
    }
}

void TestSuite::printResults(){
    std::cout << "\n" << std::string(50, '=') << "\n";
    std::cout << "Test Suite: " << this->suiteName << "\n";
    std::cout << "Tests run: " << this->testsRun << "\n";
    std::cout << "Tests passed: " << this->testsPassed << "\n";
    std::cout << "Tests failed: " << (this->testsRun - this->testsPassed) << "\n";

    if(this->testsPassed == this->testsRun) {
        std::cout << "✓ ALL TESTS PASSED" << "\n";
    } else {
        std::cout << "✗ SOME TESTS FAILED:" << "\n";
        for (const std::string& failure : this->failedTests) {
            std::cout << "  - " << failure << "\n";
        }
    }
    std::cout << std::string(50, '=') << std::endl;
}

bool TestSuite::allPassed() const{
    return this->testsPassed == testsRun;
}

int TestSuite::getFailedCount() const {
    return this->testsRun - this->testsPassed;
}
