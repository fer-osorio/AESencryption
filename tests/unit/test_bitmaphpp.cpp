// test_bitmap.cpp - Comprehensive unit test suite for Bitmap class
#include "../../file-handlers/include/bitmap.hpp"
#include "../include/test_framework.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

// ============================================================================
// Test Suite Functions
// ============================================================================

void testConstructors(TestFramework::TestSuite& suite, File::BitmapTestFixture& fixture) {
    std::cout << "\n=== Constructor Tests ===" << std::endl;

    // Test 1: Valid path constructor
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.validBmpPath);
        return true; // Should not throw
    }, "Constructor with valid path");

    // Test 2: Constructor doesn't throw on nonexistent file (loading should)
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.nonexistentPath);
        return true; // Constructor accepts path, load() will validate
    }, "Constructor with nonexistent path");

    // Test 3: Copy constructor
    RUN_TEST([&]() {
        File::Bitmap bmp1(fixture.validBmpPath);
        bmp1.load();
        File::Bitmap bmp2(bmp1);

        ASSERT_EQUAL(bmp1.PixelAmount(), bmp2.PixelAmount(), "Copy has same pixel count");
        ASSERT_EQUAL(bmp1.dataSize(), bmp2.dataSize(), "Copy has same data size");
        ASSERT_TRUE(bmp1 == bmp2, "Copy is equal to original");

        return SUITE_PASSED();
    }, "Copy constructor preserves data");
}

void testLoadOperations(TestFramework::TestSuite& suite, File::BitmapTestFixture& fixture) {
    std::cout << "\n=== Load Operation Tests ===" << std::endl;

    // Test 1: Load valid bitmap
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();

        ASSERT_TRUE(bmp.PixelAmount() > 0, "Loaded bitmap has pixels");
        ASSERT_TRUE(bmp.dataSize() > 0, "Loaded bitmap has data");
        ASSERT_EQUAL(100, static_cast<int>(bmp.PixelAmount()), "10x10 image has 100 pixels");

        return SUITE_PASSED();
    }, "Load valid 24-bit bitmap");

    // Test 2: Load small bitmap
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.smallBmpPath);
        bmp.load();

        ASSERT_EQUAL(4, static_cast<int>(bmp.PixelAmount()), "2x2 image has 4 pixels");

        return SUITE_PASSED();
    }, "Load small 2x2 bitmap");

    // Test 3: Load large bitmap
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.largeBmpPath);
        bmp.load();

        ASSERT_EQUAL(10000, static_cast<int>(bmp.PixelAmount()), "100x100 image has 10000 pixels");

        return SUITE_PASSED();
    }, "Load large 100x100 bitmap");

    // Test 4: Load nonexistent file throws exception
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::Bitmap bmp(fixture.nonexistentPath);
        bmp.load();
    }, "Load nonexistent file throws");

    // Test 5: Load file with wrong magic bytes throws
    ASSERT_THROWS(std::runtime_error, [&]() {
        File::Bitmap bmp(fixture.wrongMagicPath);
        bmp.load();
    }, "Load wrong magic bytes throws");

    // Test 6: Load corrupt header throws
    ASSERT_THROWS_ANY([&]() {
        File::Bitmap bmp(fixture.corruptHeaderPath);
        bmp.load();
    }, "Load corrupt header throws");
}

void testSaveOperations(TestFramework::TestSuite& suite, File::BitmapTestFixture& fixture) {
    std::cout << "\n=== Save Operation Tests ===" << std::endl;

    // Test 1: Save and reload bitmap
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();

        fs::path outputPath = fixture.testDataDir / "output_save_test.bmp";
        bmp.save(outputPath);

        ASSERT_TRUE(fs::exists(outputPath), "Output file was created");

        // Reload and verify
        File::Bitmap bmpReloaded(outputPath);
        bmpReloaded.load();

        ASSERT_EQUAL(bmp.PixelAmount(), bmpReloaded.PixelAmount(), "Reloaded pixel count matches");
        ASSERT_EQUAL(bmp.dataSize(), bmpReloaded.dataSize(), "Reloaded data size matches");
        ASSERT_TRUE(bmp == bmpReloaded, "Reloaded bitmap equals original");

        fs::remove(outputPath);
        return SUITE_PASSED();
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
}

void testAssignmentOperators(TestFramework::TestSuite& suite, File::BitmapTestFixture& fixture) {
    std::cout << "\n=== Assignment Operator Tests ===" << std::endl;

    // Test 1: Assignment operator
    RUN_TEST([&]() {
        File::Bitmap bmp1(fixture.validBmpPath);
        File::Bitmap bmp2(fixture.smallBmpPath);

        bmp1.load();
        bmp2.load();

        size_t originalPixels = bmp1.PixelAmount();

        bmp2 = bmp1; // Assignment

        ASSERT_EQUAL(originalPixels, bmp2.PixelAmount(), "Assignment copies pixel count");
        ASSERT_TRUE(bmp1 == bmp2, "Assignment makes bitmaps equal");

        return SUITE_PASSED();
    }, "Assignment operator copies data");

    // Test 2: Self-assignment
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();

        size_t originalPixels = bmp.PixelAmount();

        bmp = bmp; // Self-assignment

        ASSERT_EQUAL(originalPixels, bmp.PixelAmount(), "Self-assignment preserves data");

        return SUITE_PASSED();
    }, "Self-assignment is safe");
}

void testEqualityOperators(TestFramework::TestSuite& suite, File::BitmapTestFixture& fixture) {
    std::cout << "\n=== Equality Operator Tests ===" << std::endl;

    // Test 1: Same file loaded twice is equal
    RUN_TEST([&]() {
        File::Bitmap bmp1(fixture.validBmpPath);
        File::Bitmap bmp2(fixture.validBmpPath);

        bmp1.load();
        bmp2.load();

        ASSERT_TRUE(bmp1 == bmp2, "Same file equals itself");
        ASSERT_TRUE(!(bmp1 != bmp2), "Inequality operator consistent");

        return SUITE_PASSED();
    }, "Same file equality");

    // Test 2: Different files are not equal
    RUN_TEST([&]() {
        File::Bitmap bmp1(fixture.validBmpPath);
        File::Bitmap bmp2(fixture.smallBmpPath);

        bmp1.load();
        bmp2.load();

        ASSERT_TRUE(bmp1 != bmp2, "Different files not equal");
        ASSERT_TRUE(!(bmp1 == bmp2), "Equality operator consistent");

        return SUITE_PASSED();
    }, "Different files inequality");

    // Test 3: Copy is equal to original
    RUN_TEST([&]() {
        File::Bitmap bmp1(fixture.validBmpPath);
        bmp1.load();

        File::Bitmap bmp2(bmp1);

        ASSERT_TRUE(bmp1 == bmp2, "Copy equals original");

        return SUITE_PASSED();
    }, "Copy equality");
}

void testStreamOutput(TestFramework::TestSuite& suite, File::BitmapTestFixture& fixture) {
    std::cout << "\n=== Stream Output Tests ===" << std::endl;

    // Test 1: Stream output produces content
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.validBmpPath);
        bmp.load();

        std::ostringstream oss;
        oss << bmp;

        std::string output = oss.str();
        ASSERT_TRUE(output.length() > 0, "Stream output not empty");
        ASSERT_TRUE(output.find("Bitmap") != std::string::npos ||
                    output.length() > 10, "Stream output contains data");

        return SUITE_PASSED();
    }, "Stream output operator works");
}

void testEdgeCases(TestFramework::TestSuite& suite, File::BitmapTestFixture& fixture) {
    std::cout << "\n=== Edge Case Tests ===" << std::endl;

    // Test 1: Multiple loads on same object
    RUN_TEST([&]() {
        File::Bitmap bmp(fixture.validBmpPath);

        bmp.load();
        size_t firstLoad = bmp.PixelAmount();

        bmp.load(); // Load again
        size_t secondLoad = bmp.PixelAmount();

        ASSERT_EQUAL(firstLoad, secondLoad, "Multiple loads consistent");

        return SUITE_PASSED();
    }, "Multiple loads on same bitmap");

    // Test 2: Load, modify path, load again
    RUN_TEST([&]() {
        File::Bitmap bmp1(fixture.smallBmpPath);
        bmp1.load();
        size_t smallPixels = bmp1.PixelAmount();

        // Create new bitmap with different file
        File::Bitmap bmp2(fixture.validBmpPath);
        bmp2.load();
        size_t largePixels = bmp2.PixelAmount();

        ASSERT_TRUE(largePixels > smallPixels, "Different files have different sizes");

        return SUITE_PASSED();
    }, "Different bitmaps have different data");
}

void testMemorySafety(TestFramework::TestSuite& suite, File::BitmapTestFixture& fixture) {
    std::cout << "\n=== Memory Safety Tests ===" << std::endl;

    // Test 1: Destructor doesn't crash after load
    RUN_TEST([&]() {
        {
            File::Bitmap bmp(fixture.validBmpPath);
            bmp.load();
            // Destructor called here
        }
        return true; // If we get here, no crash
    }, "Destructor after load");

    // Test 2: Destructor doesn't crash without load
    RUN_TEST([&]() {
        {
            File::Bitmap bmp(fixture.validBmpPath);
            // Destructor called without load
        }
        return true;
    }, "Destructor without load");

    // Test 3: Multiple copies and assignments
    RUN_TEST([&]() {
        File::Bitmap bmp1(fixture.validBmpPath);
        bmp1.load();

        {
            File::Bitmap bmp2(bmp1);
            File::Bitmap bmp3(fixture.smallBmpPath);
            bmp3 = bmp2;
            // All destructors called here
        }

        // Original still valid
        ASSERT_TRUE(bmp1.PixelAmount() > 0, "Original still valid after copies destroyed");

        return SUITE_PASSED();
    }, "Multiple copies memory safety");
}

// ============================================================================
// Main Test Runner
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  BITMAP CLASS COMPREHENSIVE TEST SUITE" << std::endl;
    std::cout << "========================================" << std::endl;

    TEST_SUITE("Bitmap Comprehensive Tests");
    File::BitmapTestFixture fixture;

    // Run all test categories
    testConstructors(suite, fixture);
    testLoadOperations(suite, fixture);
    testSaveOperations(suite, fixture);
    testAssignmentOperators(suite, fixture);
    testEqualityOperators(suite, fixture);
    testStreamOutput(suite, fixture);
    testEdgeCases(suite, fixture);
    testMemorySafety(suite, fixture);

    // Print final results
    std::cout << "\n========================================" << std::endl;
    PRINT_RESULTS();
    std::cout << "========================================" << std::endl;

    return suite.allPassed() ? 0 : 1;
}
