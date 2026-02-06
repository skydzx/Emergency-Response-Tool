#include "test_security.h"
#include "SecurityUtils.h"
#include <QDebug>
#include <QTemporaryFile>

int test_count = 0;
int test_passed = 0;
int test_failed = 0;

void test(const QString& name, bool result) {
    test_count++;
    if (result) {
        test_passed++;
        qDebug() << "[PASS]" << name;
    } else {
        test_failed++;
        qDebug() << "[FAIL]" << name;
    }
}

std::tuple<int, int, int> runSecurityTests(bool verbose) {
    Q_UNUSED(verbose)
    test_count = 0;
    test_passed = 0;
    test_failed = 0;

    qDebug() << "\n========== Security Utils Tests ==========";

    // Test file path validation
    test("Valid File Path", SecurityUtils::validateFilePath("C:\\Windows\\System32\\cmd.exe"));
    test("Invalid File Path (traversal)", !SecurityUtils::validateFilePath("C:\\..\\etc\\passwd"));
    test("Invalid File Path (null chars)", !SecurityUtils::validateFilePath("C:\\test\x00file.exe"));

    // Test URL validation
    test("Valid HTTPS URL", SecurityUtils::validateUrl("https://www.example.com"));
    test("Invalid URL", !SecurityUtils::validateUrl("not a url"));

    // Test IP address validation
    test("Valid IP Address", SecurityUtils::validateIpAddress("192.168.1.1"));
    test("Invalid IP Address", !SecurityUtils::validateIpAddress("999.999.999.999"));

    // Test domain validation
    test("Valid Domain", SecurityUtils::validateDomain("www.example.com"));
    test("Invalid Domain", !SecurityUtils::validateDomain("-invalid.com"));

    // Test hash validation
    test("Valid SHA256 Hash", SecurityUtils::validateHash(
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"));
    test("Invalid Hash Length", !SecurityUtils::validateHash("abc123", "sha256"));

    // Test input sanitization
    QString sanitized = SecurityUtils::sanitizeInput("test; rm -rf /");
    test("Sanitize Input (remove semicolon)", !sanitized.contains(";"));
    test("Sanitize Input (remove pipe)", !sanitized.contains("|"));

    // Test HTML escaping
    QString escaped = SecurityUtils::escapeHtml("<script>alert('xss')</script>");
    test("Escape HTML (no script tag)", !escaped.contains("<script>"));

    // Test file safety
    QTemporaryFile tempFile;
    tempFile.open();
    tempFile.write("test");
    tempFile.close();
    test("Safe File Check", SecurityUtils::isSafeFile(tempFile.fileName()));

    // Test file name sanitization
    QString safeName = SecurityUtils::sanitizeFileName("../../../etc/passwd");
    test("Sanitize File Name (remove dots)", safeName != "../../../etc/passwd");

    // Test path traversal detection
    test("Detect Path Traversal", SecurityUtils::isPathTraversal("../etc/passwd"));
    test("Detect Path Traversal (encoded)", SecurityUtils::isPathTraversal("%2e%2e/etc/passwd"));

    // Test password hashing
    QString password = "testPassword123";
    QString salt = "randomSalt";
    QString hashed = SecurityUtils::hashPassword(password, salt);
    test("Password Hashing", !hashed.isEmpty() && hashed.length() == 64);

    // Test password verification
    bool verifyResult = SecurityUtils::verifyPassword(password, hashed, salt);
    test("Password Verification", verifyResult);

    // Test token generation
    QString token = SecurityUtils::generateToken(32);
    test("Token Generation", token.length() == 32);

    // Test salt generation
    QString salt2 = SecurityUtils::generateSalt(16);
    test("Salt Generation", salt2.length() == 16);

    qDebug() << "\nSecurity Tests Results:";
    qDebug() << "Total:" << test_count;
    qDebug() << "Passed:" << test_passed;
    qDebug() << "Failed:" << test_failed;

    return {test_count, test_passed, test_failed};
}
