Excellent question! Mocks and stubs are fundamental concepts in software testing that often confuse developers. Let me provide a comprehensive explanation.

## **Definitions and Core Concepts**

### **Stubs**
A **stub** is a minimal implementation that provides predefined responses to method calls during testing. It's like a "dummy" version of a real component that always returns the same, predictable values.

```cpp
// Real database class
class UserDatabase {
public:
    User getUserById(int id) {
        // Complex database query logic
        return query_database(id);
    }
};

// Stub version for testing
class UserDatabaseStub : public UserDatabase {
public:
    User getUserById(int id) override {
        // Always returns the same test user
        return User{123, "Test User", "test@example.com"};
    }
};
```

### **Mocks**
A **mock** is a sophisticated test double that not only provides predefined responses but also **records and verifies** how it was used. Mocks can assert that specific methods were called with expected parameters, in the right order, and the correct number of times.

```cpp
// Mock example (conceptual - would use a mocking framework)
class UserDatabaseMock : public UserDatabase {
private:
    int getUserByIdCallCount = 0;
    std::vector<int> receivedIds;
    
public:
    User getUserById(int id) override {
        getUserByIdCallCount++;
        receivedIds.push_back(id);
        return User{id, "Mock User", "mock@example.com"};
    }
    
    // Verification methods
    void verifyGetUserByIdCalledOnce() {
        assert(getUserByIdCallCount == 1);
    }
    
    void verifyCalledWithId(int expectedId) {
        assert(std::find(receivedIds.begin(), receivedIds.end(), expectedId) != receivedIds.end());
    }
};
```

## **Historical Context and Development**

### **Origins (1990s)**
The concepts emerged from the **Smalltalk community** and **Extreme Programming (XP)** movement:

- **Kent Beck** and others in XP advocated for extensive unit testing
- Early **Smalltalk** developers needed ways to isolate objects for testing
- The term "mock object" was coined by **Tim Mackinnon, Steve Freeman, and Philip Craig** in their 2000 paper "Mock Roles, Not Objects"

### **Evolution Timeline**

**Early 2000s**: Manual test doubles
```cpp
// Hand-written test doubles
class TestEmailService : public EmailService {
public:
    bool sendEmail(const Email& email) override {
        sent_emails.push_back(email);
        return true; // Always succeed for testing
    }
    std::vector<Email> sent_emails;
};
```

**Mid-2000s**: Mocking frameworks emerged
- **Java**: EasyMock (2001), Mockito (2007)
- **C#**: Rhino Mocks (2005)
- **C++**: Google Mock (2008)

**Modern Era**: Advanced mocking with fluent APIs
```cpp
// Modern Google Mock example
EXPECT_CALL(mock_database, getUserById(123))
    .Times(1)
    .WillOnce(Return(test_user));
```

## **Why Use Mocks/Stubs for Dependencies?**

### **1. Isolation and Control**
```cpp
// Without mocks - testing becomes complex
void test_user_service() {
    UserService service; // Depends on real database, email service, etc.
    service.registerUser("john@example.com");
    
    // Problems:
    // - Real database must be set up
    // - Email might actually be sent
    // - Network issues could cause test failure
    // - Slow execution due to I/O
}

// With mocks - isolated testing
void test_user_service() {
    MockDatabase mock_db;
    MockEmailService mock_email;
    UserService service(&mock_db, &mock_email);
    
    EXPECT_CALL(mock_db, saveUser(_)).Times(1);
    EXPECT_CALL(mock_email, sendWelcomeEmail(_)).Times(1);
    
    service.registerUser("john@example.com");
    
    // Test focuses only on UserService logic
    // Fast, reliable, isolated
}
```

### **2. Testing Error Conditions**
```cpp
// Easy to simulate failures with mocks
TEST(UserService, HandlesDatabase Error) {
    MockDatabase mock_db;
    UserService service(&mock_db);
    
    // Simulate database failure
    EXPECT_CALL(mock_db, saveUser(_))
        .WillOnce(Throw(DatabaseException("Connection failed")));
    
    EXPECT_THROW(service.registerUser("test@example.com"), ServiceException);
}
```

### **3. Verifying Interactions**
```cpp
// Mocks can verify behavior, not just state
TEST(UserService, CallsEmailServiceAfterSaving) {
    MockDatabase mock_db;
    MockEmailService mock_email;
    UserService service(&mock_db, &mock_email);
    
    // Verify order of operations
    InSequence seq;
    EXPECT_CALL(mock_db, saveUser(_));
    EXPECT_CALL(mock_email, sendWelcomeEmail(_));
    
    service.registerUser("test@example.com");
}
```

## **Applied to Your AES Project**
```cpp
// Example: Testing your Cipher class in isolation using mocks

// 1. STUB Example - For unit testing Cipher without real C functions
class AESStub {
public:
    // Always returns success
    static enum ExceptionCode encryptECB(const uint8_t* input, size_t size, 
                                        const uint8_t* keyexpansion, size_t keylenbits, 
                                        uint8_t* output) {
        // Predictable "encryption" for testing
        for(size_t i = 0; i < size; ++i) {
            output[i] = input[i] ^ 0xAA; // Simple XOR for testing
        }
        return SUCCESS_CODE;
    }
    
    static enum ExceptionCode encryptCBC(const uint8_t* input, size_t size,
                                        const uint8_t* keyexpansion, size_t keylenbits,
                                        const uint8_t* IV, uint8_t* output) {
        // Predictable CBC "encryption"
        for(size_t i = 0; i < size; ++i) {
            output[i] = input[i] ^ IV[i % 16] ^ 0xBB;
        }
        return SUCCESS_CODE;
    }
};

// Unit test using stub
TEST(CipherUnitTest, EncryptionCallsCorrectMode) {
    // Replace real C functions with stubs during compilation
    #define encryptECB AESStub::encryptECB
    #define encryptCBC AESStub::encryptCBC
    
    uint8_t test_data[16] = {0x01, 0x02, 0x03, /*...*/};
    uint8_t output[16];
    
    AESencryption::Key key(test_key, Key::LenBits::_128, Key::OpMode::ECB);
    AESencryption::Cipher cipher(key);
    
    cipher.encrypt(test_data, 16, output);
    
    // We can predict the output because we control the stub
    for(int i = 0; i < 16; ++i) {
        ASSERT_EQUAL(test_data[i] ^ 0xAA, output[i], "Stub encryption should XOR with 0xAA");
    }
}

// 2. MOCK Example - For verifying behavior
class MockFileHandler {
private:
    mutable int readCallCount = 0;
    mutable int writeCallCount = 0;
    mutable std::vector<std::string> writtenFiles;
    
public:
    std::vector<uint8_t> readFile(const std::string& filename) const {
        readCallCount++;
        // Return predictable test data
        return {0x01, 0x02, 0x03, 0x04, /*...test data...*/};
    }
    
    void writeFile(const std::string& filename, const std::vector<uint8_t>& data) const {
        writeCallCount++;
        writtenFiles.push_back(filename);
        // Don't actually write to disk
    }
    
    // Verification methods
    void verifyReadCalledOnce() const { assert(readCallCount == 1); }
    void verifyWriteCalledOnce() const { assert(writeCallCount == 1); }
    void verifyWroteToFile(const std::string& filename) const {
        assert(std::find(writtenFiles.begin(), writtenFiles.end(), filename) != writtenFiles.end());
    }
};

// Integration test using mock
TEST(FileEncryptionIntegration, EncryptsAndSavesFile) {
    MockFileHandler mock_handler;
    AESencryption::Key key(test_key, Key::LenBits::_128, Key::OpMode::ECB);
    
    // Class under test that combines file handling and encryption
    FileEncryptor encryptor(&mock_handler, key);
    
    encryptor.encryptFile("input.txt", "output.enc");
    
    // Verify the right sequence of operations occurred
    mock_handler.verifyReadCalledOnce();
    mock_handler.verifyWriteCalledOnce();
    mock_handler.verifyWroteToFile("output.enc");
}

// 3. Stub for testing error handling
class ErrorInjectingStub {
public:
    static bool should_fail;
    static enum ExceptionCode encryptECB(const uint8_t* input, size_t size,
                                        const uint8_t* keyexpansion, size_t keylenbits,
                                        uint8_t* output) {
        if (should_fail) {
            return ERROR_INVALID_INPUT; // Inject error
        }
        return SUCCESS_CODE;
    }
};

bool ErrorInjectingStub::should_fail = false;

TEST(CipherErrorHandling, HandlesEncryptionFailure) {
    #define encryptECB ErrorInjectingStub::encryptECB
    
    ErrorInjectingStub::should_fail = true;
    
    AESencryption::Key key(test_key, Key::LenBits::_128, Key::OpMode::ECB);
    AESencryption::Cipher cipher(key);
    
    uint8_t test_data[16] = {0x01, /*...*/};
    uint8_t output[16];
    
    // Your Cipher class should handle the error appropriately
    EXPECT_THROW(cipher.encrypt(test_data, 16, output), std::runtime_error);
}

// 4. Mock for metrics/analysis testing
class MockRandomnessAnalyzer {
private:
    mutable std::vector<std::vector<uint8_t>> analyzed_data;
    
public:
    double calculateEntropy(const std::vector<uint8_t>& data) const {
        analyzed_data.push_back(data);
        return 7.8; // Mock high entropy result
    }
    
    bool passesRandomnessTest(const std::vector<uint8_t>& data) const {
        analyzed_data.push_back(data);
        return true; // Always pass for testing
    }
    
    // Verification
    void verifyAnalyzedDataCount(size_t expected) const {
        assert(analyzed_data.size() == expected);
    }
    
    void verifyAnalyzedSpecificData(const std::vector<uint8_t>& expected) const {
        assert(std::find(analyzed_data.begin(), analyzed_data.end(), expected) != analyzed_data.end());
    }
};

TEST(EncryptionQualityTest, AnalyzesEncryptedData) {
    MockRandomnessAnalyzer mock_analyzer;
    AESencryption::Cipher cipher(test_key);
    
    uint8_t plaintext[32] = {0x00, 0x00, /*...repeated pattern...*/};
    uint8_t ciphertext[32];
    
    cipher.encrypt(plaintext, 32, ciphertext);
    
    // Test that encrypted data gets analyzed
    std::vector<uint8_t> cipher_vec(ciphertext, ciphertext + 32);
    double entropy = mock_analyzer.calculateEntropy(cipher_vec);
    bool passes = mock_analyzer.passesRandomnessTest(cipher_vec);
    
    mock_analyzer.verifyAnalyzedDataCount(2); // Called twice
    ASSERT_TRUE(entropy > 7.0, "Encrypted data should have high entropy");
    ASSERT_TRUE(passes, "Encrypted data should pass randomness tests");
}
``` 


## **Common Use Cases**

### **1. External Dependencies**
- Database connections
- Network services (APIs, web services)
- File systems
- Hardware interfaces
- Third-party libraries

### **2. Complex Setup Requirements**
- Components requiring extensive configuration
- Services with complex initialization
- Resources that are expensive to create

### **3. Non-Deterministic Behavior**
- Random number generators
- Time-dependent functions
- Concurrent operations
- Network latency variations

### **4. Error Condition Testing**
- Simulating network failures
- Database connection timeouts
- Out-of-memory conditions
- Invalid input scenarios

## **Common Misuses and Pitfalls**

### **1. Over-Mocking (The "Mock Everything" Anti-Pattern)**
```cpp
// BAD - mocking value objects and simple data structures
MockString mock_filename;
MockInt mock_key_length;
MockVector mock_data;

// GOOD - only mock complex dependencies
MockDatabase mock_db;
MockNetworkService mock_network;
```

### **2. Mocking Internal Implementation Details**
```cpp
// BAD - testing implementation instead of behavior
EXPECT_CALL(mock_internal_parser, parseHeader(_)).Times(1);
EXPECT_CALL(mock_internal_validator, validateData(_)).Times(1);

// GOOD - testing public behavior
result = processor.processFile("test.dat");
ASSERT_EQUAL(EXPECTED_OUTPUT, result);
```

### **3. Brittle Tests from Over-Specification**
```cpp
// BAD - too specific about internal calls
EXPECT_CALL(mock_db, connect()).Times(1);
EXPECT_CALL(mock_db, beginTransaction()).Times(1);
EXPECT_CALL(mock_db, executeQuery("SELECT * FROM users WHERE id = 123")).Times(1);
EXPECT_CALL(mock_db, commitTransaction()).Times(1);
EXPECT_CALL(mock_db, disconnect()).Times(1);

// GOOD - focus on essential interactions
EXPECT_CALL(mock_db, getUserById(123)).WillOnce(Return(test_user));
```

### **4. Not Testing Real Integrations**
```cpp
// Problem: Only testing with mocks, never with real dependencies
// Solution: Have both unit tests (with mocks) AND integration tests (with real dependencies)
```

## **When NOT to Use Mocks/Stubs**

1. **Value Objects**: Don't mock strings, numbers, simple data structures
2. **Objects Under Test**: Never mock the class you're actually testing
3. **Integration Tests**: Use real dependencies to test actual integration
4. **End-to-End Tests**: Use the real system for full workflow validation

## **Best Practices Summary**

1. **Use stubs for state** (return predictable values)
2. **Use mocks for behavior** (verify interactions)
3. **Mock at architectural boundaries** (network, database, file system)
4. **Keep mocks simple** - complex mocks often indicate design problems
5. **Have both unit tests (with mocks) and integration tests (without mocks)**
6. **Mock roles, not objects** - focus on what the dependency does, not what it is

The key insight: **Mocks and stubs are tools for isolation, not replacement for integration testing.** They allow you to test your component's logic independently, but you still need integration tests to ensure components actually work together correctly.
