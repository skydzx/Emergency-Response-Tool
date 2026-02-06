#include "test_database.h"
#include "test_process_detector.h"
#include "test_network_detector.h"
#include "test_file_analyzer.h"
#include "test_threat_dictionary.h"
#include "test_security.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDebug>

void printUsage() {
    qDebug() << "Usage: EmergencyResponseToolTests [test_category]";
    qDebug() << "";
    qDebug() << "Available test categories:";
    qDebug() << "  Database     - Test database operations";
    qDebug() << "  Process      - Test process detection";
    qDebug() << "  Network      - Test network detection";
    qDebug() << "  File         - Test file analysis";
    qDebug() << "  Threat       - Test threat dictionary";
    qDebug() << "  Security     - Test security utilities";
    qDebug() << "  All          - Run all tests (default)";
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    app.setApplicationName("EmergencyResponseToolTests");
    app.setApplicationVersion("1.0.0");

    // 设置测试目录
    QDir::setCurrent(QCoreApplication::applicationDirPath());

    // 命令行解析
    QCommandLineParser parser;
    parser.setApplicationDescription("Emergency Response Tool - Unit Tests");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption verboseOption("v", "Verbose output", "verbose");
    parser.addOption(verboseOption);

    parser.process(app);

    bool verbose = parser.isSet(verboseOption);
    QString category = parser.positionalArguments().isEmpty() ?
                       "All" : parser.positionalArguments().first();

    qDebug() << "===========================================";
    qDebug() << "Emergency Response Tool - Unit Tests";
    qDebug() << "===========================================";
    qDebug() << "Test Category:" << category;
    qDebug() << "===========================================";

    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;

    // 运行数据库测试
    if (category == "All" || category == "Database") {
        auto [total, passed, failed] = runDatabaseTests(verbose);
        totalTests += total;
        passedTests += passed;
        failedTests += failed;
    }

    // 运行进程检测测试
    if (category == "All" || category == "Process") {
        auto [total, passed, failed] = runProcessDetectorTests(verbose);
        totalTests += total;
        passedTests += passed;
        failedTests += failed;
    }

    // 运行网络检测测试
    if (category == "All" || category == "Network") {
        auto [total, passed, failed] = runNetworkDetectorTests(verbose);
        totalTests += total;
        passedTests += passed;
        failedTests += failed;
    }

    // 运行文件分析测试
    if (category == "All" || category == "File") {
        auto [total, passed, failed] = runFileAnalyzerTests(verbose);
        totalTests += total;
        passedTests += passed;
        failedTests += failed;
    }

    // 运行威胁字典测试
    if (category == "All" || category == "Threat") {
        auto [total, passed, failed] = runThreatDictionaryTests(verbose);
        totalTests += total;
        passedTests += passed;
        failedTests += failed;
    }

    // 运行安全测试
    if (category == "All" || category == "Security") {
        auto [total, passed, failed] = runSecurityTests(verbose);
        totalTests += total;
        passedTests += passed;
        failedTests += failed;
    }

    // 输出结果
    qDebug() << "===========================================";
    qDebug() << "Test Results Summary";
    qDebug() << "===========================================";
    qDebug() << "Total Tests:" << totalTests;
    qDebug() << "Passed:" << passedTests;
    qDebug() << "Failed:" << failedTests;
    qDebug() << "Pass Rate:" << QString::number(totalTests > 0 ?
               (double)passedTests / totalTests * 100 : 0, 'f', 2) << "%";
    qDebug() << "===========================================";

    if (failedTests > 0) {
        qDebug() << "RESULT: FAILED";
        return 1;
    }

    qDebug() << "RESULT: ALL TESTS PASSED";
    return 0;
}
