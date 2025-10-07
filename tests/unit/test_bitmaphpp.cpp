// Comprehensive unit test suite for Bitmap class
#include "../../file-handlers/include/bitmap.hpp"
#include "../include/bitmap_fixture.hpp"
#include "../include/test_framework.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

// ============================================================================
// Test Suite Functions
// ============================================================================

bool test_Constructors(BitmapTestFixture& fixture);
bool test_LoadOperations(BitmapTestFixture& fixture);
bool test_SaveOperations(BitmapTestFixture& fixture);
bool test_AssignmentOperators(BitmapTestFixture& fixture);
bool test_EqualityOperators(BitmapTestFixture& fixture);
bool test_StreamOutput(BitmapTestFixture& fixture);
bool test_EdgeCases(BitmapTestFixture& fixture);
bool test_MemorySafety(BitmapTestFixture& fixture);

// ============================================================================
// Principal Test Runner
// ============================================================================
bool runAllTests();

int main() {
    return runAllTests() ? 0 : 1;
}

bool test_Constructors(BitmapTestFixture& fixture) {
    TEST_SUITE("Constructor Tests");

    // Test 1: Valid path constructor
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp(fixture.validBmpPath);
        return true; // Should not throw
    }, "Constructor with valid path");

    // Test 2: Construct nonexistent file throws exception
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::Bitmap bmp(fixture.nonexistentPath);
    }, "Construct nonexistent file throws");

    // Test 3: Copy constructor
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp1(fixture.validBmpPath);
        bmp1.load();
        File::Bitmap bmp2(bmp1);
        return
            ASSERT_EQUAL(bmp1.PixelAmount(), bmp2.PixelAmount(), "Copy has same pixel count") &&
            ASSERT_EQUAL(bmp1.dataSize(), bmp2.dataSize(), "Copy has same data size") &&
            ASSERT_TRUE(bmp1 == bmp2, "Copy is equal to original");
    }, "Copy constructor preserves data");

    // Test 4: Constructor: File with wrong magic bytes throws
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::Bitmap bmp(fixture.wrongMagicPath);
        bmp.load();
    }, "Load wrong magic bytes throws");

    // Test 5: Constructor: corrupt header throws
    ASSERT_THROWS_ANY([&]() {
        File::Bitmap bmp(fixture.corruptHeaderPath);
        bmp.load();
    }, "Constructor: corrupt header throws");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_LoadOperations(BitmapTestFixture& fixture) {
    TEST_SUITE("Load Operation Tests");

    // Test 1: Load valid bitmap
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();
        return
            ASSERT_TRUE(bmp.PixelAmount() > 0, "Loaded bitmap has pixels") &&
            ASSERT_TRUE(bmp.dataSize() > 0, "Loaded bitmap has data") &&
            ASSERT_EQUAL(100, static_cast<int>(bmp.PixelAmount()), "10x10 image has 100 pixels");
    }, "Load valid 24-bit bitmap");

    // Test 2: Load small bitmap
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp(fixture.smallBmpPath);
        bmp.load();
        return ASSERT_EQUAL(4, static_cast<int>(bmp.PixelAmount()), "2x2 image has 4 pixels");
    }, "Load small 2x2 bitmap");

    // Test 3: Load large bitmap
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp(fixture.largeBmpPath);
        bmp.load();
        return ASSERT_EQUAL(10000, static_cast<int>(bmp.PixelAmount()), "100x100 image has 10000 pixels");
    }, "Load large 100x100 bitmap");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_SaveOperations(BitmapTestFixture& fixture) {
    TEST_SUITE("Save Operation Tests");

    // Test 1: Save and reload bitmap
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();

        fs::path outputPath = fixture.testDataDir / "output_save_test.bmp";
        bmp.save(outputPath);

        bool assertOutputExist = ASSERT_TRUE(fs::exists(outputPath), "Output file was created");

        // Reload and verify
        File::Bitmap bmpReloaded(outputPath);
        bmpReloaded.load();

        bool reloadAndVerify =
            ASSERT_EQUAL(bmp.PixelAmount(), bmpReloaded.PixelAmount(), "Reloaded pixel count matches") &&
            ASSERT_EQUAL(bmp.dataSize(), bmpReloaded.dataSize(), "Reloaded data size matches") &&
            ASSERT_TRUE(bmp == bmpReloaded, "Reloaded bitmap equals original");

        fs::remove(outputPath);
        return assertOutputExist && reloadAndVerify;
    }, "Save and reload preserves data");

    // Test 2: Save to invalid directory throws
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();
        bmp.save("/invalid/nonexistent/directory/output.bmp");
    }, "Save to invalid directory throws");

    // Test 3: Save without loading throws
    ASSERT_THROWS(std::logic_error, [&]() {
        File::Bitmap bmp(fixture.validBmpPath);
        // Don't call load()
        bmp.save(fixture.testDataDir / "should_fail.bmp");
    }, "Save without load throws");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_AssignmentOperators(BitmapTestFixture& fixture) {
    TEST_SUITE("Assignment Operator Tests");

    // Test 1: Assignment operator
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp1(fixture.validBmpPath);
        File::Bitmap bmp2(fixture.smallBmpPath);
        bmp1.load();
        bmp2.load();

        size_t originalPixels = bmp1.PixelAmount();
        bmp2 = bmp1; // Assignment

        return
            ASSERT_EQUAL(originalPixels, bmp2.PixelAmount(), "Assignment copies pixel count") &&
            ASSERT_TRUE(bmp1 == bmp2, "Assignment makes bitmaps equal");
    }, "Assignment operator copies data");

    // Test 2: Self-assignment
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();

        size_t originalPixels = bmp.PixelAmount();
        bmp = bmp; // Self-assignment

        return ASSERT_EQUAL(originalPixels, bmp.PixelAmount(), "Self-assignment preserves data");
    }, "Self-assignment is safe");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_EqualityOperators(BitmapTestFixture& fixture) {
    TEST_SUITE("Equality Operator Tests");

    // Test 1: Same file loaded twice is equal
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp1(fixture.validBmpPath);
        File::Bitmap bmp2(fixture.validBmpPath);
        bmp1.load();
        bmp2.load();
        return
            ASSERT_TRUE(bmp1 == bmp2, "Same file equals itself") &&
            ASSERT_TRUE(!(bmp1 != bmp2), "Inequality operator consistent");
    }, "Same file equality");

    // Test 2: Different files are not equal
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp1(fixture.validBmpPath);
        File::Bitmap bmp2(fixture.smallBmpPath);
        bmp1.load();
        bmp2.load();
        return
            ASSERT_TRUE(bmp1 != bmp2, "Different files not equal") &&
            ASSERT_TRUE(!(bmp1 == bmp2), "Equality operator consistent");
    }, "Different files inequality");

    // Test 3: Copy is equal to original
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp1(fixture.validBmpPath);
        bmp1.load();

        File::Bitmap bmp2(bmp1);

        return ASSERT_TRUE(bmp1 == bmp2, "Copy equals original");
    }, "Copy equality");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_StreamOutput(BitmapTestFixture& fixture) {
    TEST_SUITE("Stream Output Tests");

    // Test 1: Stream output produces content
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();
        std::ostringstream oss;

        oss << bmp;

        std::string output = oss.str();
        return
            ASSERT_TRUE(output.length() > 0, "Stream output not empty") &&
            ASSERT_TRUE(output.find("Bitmap") != std::string::npos || output.length() > 10, "Stream output contains data");
    }, "Stream output operator works");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_EdgeCases(BitmapTestFixture& fixture) {
    TEST_SUITE("Edge Case Tests");

    // Test 1: Multiple loads on same object
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp(fixture.validBmpPath);

        bmp.load();
        size_t firstLoad = bmp.PixelAmount();
        bmp.load(); // Load again
        size_t secondLoad = bmp.PixelAmount();

        return ASSERT_EQUAL(firstLoad, secondLoad, "Multiple loads consistent");
    }, "Multiple loads on same bitmap");

    // Test 2: Load, modify path, load again
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp1(fixture.smallBmpPath);
        bmp1.load();
        size_t smallPixels = bmp1.PixelAmount();

        // Create new bitmap with different file
        File::Bitmap bmp2(fixture.validBmpPath);
        bmp2.load();
        size_t largePixels = bmp2.PixelAmount();

        return ASSERT_TRUE(largePixels > smallPixels, "Different files have different sizes");
    }, "Different bitmaps have different data");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool test_MemorySafety(BitmapTestFixture& fixture) {
    TEST_SUITE("Memory Safety Tests");

    // Test 1: Destructor doesn't crash after load
    RUN_TEST([&]() -> bool {
        {
            File::Bitmap bmp(fixture.validBmpPath);
            bmp.load();
            // Destructor called here
        }
        return true; // If we get here, no crash
    }, "Destructor after load");

    // Test 2: Destructor doesn't crash without load
    RUN_TEST([&]() -> bool {
        {
            File::Bitmap bmp(fixture.validBmpPath);
            // Destructor called without load
        }
        return true;
    }, "Destructor without load");

    // Test 3: Multiple copies and assignments
    RUN_TEST([&]() -> bool {
        File::Bitmap bmp1(fixture.validBmpPath);
        bmp1.load();
        {
            File::Bitmap bmp2(bmp1);
            File::Bitmap bmp3(fixture.smallBmpPath);
            bmp3 = bmp2;
            // bmp2 and bmp3 destructors called here
        }
        // Original still valid
        return ASSERT_TRUE(bmp1.PixelAmount() > 0, "Original still valid after copies destroyed");
    }, "Multiple copies memory safety");

    PRINT_RESULTS();
    return SUITE_PASSED();
}

bool runAllTests(){
    std::cout << "================================================================================" << std::endl;
    std::cout << "                 BITMAP CLASS COMPREHENSIVE TEST SUITE                          " << std::endl;
    std::cout << "================================================================================" << std::endl;

    TEST_SUITE("Bitmap Comprehensive Tests");
    BitmapTestFixture fixture;
    std::cout << "\n";
    // Run all test categories
    RUN_TEST([&]() ->bool {
        return test_Constructors(fixture);
    },"Constructors");
    std::cout << "================================================================================\n\n";
    RUN_TEST([&]() ->bool {
        return test_LoadOperations(fixture);
    },"LoadOperations");
    std::cout << "================================================================================\n\n";
    RUN_TEST([&]() ->bool {
        return test_SaveOperations(fixture);
    },"Save Operations");
    std::cout << "================================================================================\n\n";
    RUN_TEST([&]() ->bool {
        return test_AssignmentOperators(fixture);
    },"Assignment Operators");
    std::cout << "================================================================================\n\n";
    RUN_TEST([&]() ->bool {
        return test_EqualityOperators(fixture);
    },"Equality Operators");
    std::cout << "================================================================================\n\n";
    RUN_TEST([&]() ->bool {
        return test_StreamOutput(fixture);
    },"Stream Output");
    std::cout << "================================================================================\n\n";
    RUN_TEST([&]() ->bool {
        return test_EdgeCases(fixture);
    },"Edge Cases");
    std::cout << "================================================================================\n\n";
    RUN_TEST([&]() ->bool {
        return test_MemorySafety(fixture);
    },"Memory Safety");

    // Print final results
    std::cout << "\n================================================================================" << std::endl;
    PRINT_RESULTS();
    std::cout << "================================================================================" << std::endl;

    return SUITE_PASSED();
}
