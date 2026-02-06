#include "test_file_analyzer.h"
#include "FileAnalyzer.h"
#include <QDebug>
#include <QTemporaryDir>

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

std::tuple<int, int, int> runFileAnalyzerTests(bool verbose) {
    Q_UNUSED(verbose)
    test_count = 0;
    test_passed = 0;
    test_failed = 0;

    qDebug() << "\n========== File Analyzer Tests ==========";

    FileAnalyzer analyzer;

    // Test hash calculation with a temporary file
    QTemporaryDir tempDir;
    QString testFile = tempDir.filePath("test.txt");
    QFile file(testFile);
    if (file.open(QIODevice::WriteOnly)) {
        file.write("Test content for hash calculation");
        file.close();
    }

    QString md5, sha1, sha256;
    bool hashCalc = analyzer.calculateFileHash(testFile, md5, sha1, sha256);
    test("Calculate File Hash", hashCalc);

    if (hashCalc) {
        if (verbose) {
            qDebug() << "MD5:" << md5;
            qDebug() << "SHA1:" << sha1;
            qDebug() << "SHA256:" << sha256;
        }
        test("MD5 Hash Valid", !md5.isEmpty() && md5.length() == 32);
        test("SHA1 Hash Valid", !sha1.isEmpty() && sha1.length() == 40);
        test("SHA256 Hash Valid", !sha256.isEmpty() && sha256.length() == 64);
    }

    // Test dangerous extension detection
    analyzer.setScanExtensions({"exe", "dll", "bat", "ps1"});
    bool isDangerous = analyzer.isDangerousExtension(".exe");
    test("Dangerous Extension Detection (.exe)", isDangerous);

    bool notDangerous = analyzer.isDangerousExtension(".txt");
    test("Safe Extension Detection (.txt)", !notDangerous);

    // Test file information retrieval
    QFileInfo info(testFile);
    bool fileInfoValid = info.exists();
    test("Get File Information", fileInfoValid);

    qDebug() << "\nFile Analyzer Tests Results:";
    qDebug() << "Total:" << test_count;
    qDebug() << "Passed:" << test_passed;
    qDebug() << "Failed:" << test_failed;

    return {test_count, test_passed, test_failed};
}
