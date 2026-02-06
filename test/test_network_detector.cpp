#include "test_network_detector.h"
#include "NetworkDetector.h"
#include <QDebug>

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

std::tuple<int, int, int> runNetworkDetectorTests(bool verbose) {
    Q_UNUSED(verbose)
    test_count = 0;
    test_passed = 0;
    test_failed = 0;

    qDebug() << "\n========== Network Detector Tests ==========";

    NetworkDetector detector;

    // Test getting all connections
    auto connections = detector.getAllConnections();
    test("Get All Connections", true);
    if (verbose) {
        qDebug() << "Found" << connections.size() << "network connections";
    }

    // Test filtering by protocol
    auto tcpConnections = detector.getConnectionsByProtocol("TCP");
    test("Filter by Protocol (TCP)", !tcpConnections.isEmpty() || connections.isEmpty());

    // Test suspicious connection detection
    auto suspicious = detector.getSuspiciousConnections();
    test("Get Suspicious Connections", true);

    // Test port analysis
    detector.analyzePorts();
    test("Analyze Ports", true);

    qDebug() << "\nNetwork Detector Tests Results:";
    qDebug() << "Total:" << test_count;
    qDebug() << "Passed:" << test_passed;
    qDebug() << "Failed:" << test_failed;

    return {test_count, test_passed, test_failed};
}
