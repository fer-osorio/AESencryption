// System/E2E Testing for AES Image Encryption Tool

#include <gtest/gtest.h>
#include "../include/system_workflows.hpp"

namespace cltt = CommandLineToolsTest;

TEST(SystemTest, FileEncryptionWorkflow) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, cltt::FileFormat::BITMAP);
    EXPECT_TRUE(st.test_file_encryption_workflow());
}

TEST(SystemTest, ErrorScenarios) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, cltt::FileFormat::BITMAP);
    EXPECT_TRUE(st.test_error_scenarios());
}

TEST(SystemTest, LargeFilePerformance) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, cltt::FileFormat::BITMAP);
    EXPECT_TRUE(st.test_large_file_performance());
}

TEST(SystemTest, JpegEncryptSavesAsPng) {
    cltt::SystemTests st(IMAGE_ENCRYPTOR_PATH, cltt::FileFormat::BITMAP);
    EXPECT_TRUE(st.test_jpeg_encryption_saves_as_png());
}
