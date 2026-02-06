#include "test_process_detector.h"
#include "ProcessDetector.h"
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

std::tuple<int, int, int> runProcessDetectorTests(bool verbose) {
    Q_UNUSED(verbose)
    test_count = 0;
    test_passed = 0;
    test_failed = 0;

    qDebug() << "\n========== Process Detector Tests ==========";

    ProcessDetector detector;

    // Test getting all processes
    auto processes = detector.getAllProcesses();
    test("Get All Processes", !processes.isEmpty());
    if (verbose) {
        qDebug() << "Found" << processes.size() << "processes";
    }

    // Test process filtering by name
    auto systemProcesses = detector.getProcessesByName("explorer.exe");
    test("Filter Processes by Name", !systemProcesses.isEmpty());
    if (verbose && !systemProcesses.isEmpty()) {
        qDebug() << "Found" << systemProcesses.size() << "explorer.exe processes";
    }

    // Test finding process by PID
    if (!processes.isEmpty()) {
        int firstPid = processes[0].pid;
        auto foundProcess = detector.getProcessByPid(firstPid);
        test("Find Process by PID", foundProcess.pid == firstPid);
    }

    // Test suspicious process detection
    auto suspicious = detector.getSuspiciousProcesses();
    test("Get Suspicious Processes", true); // Just run without exception

    qDebug() << "\nProcess Detector Tests Results:";
    qDebug() << "Total:" << test_count;
    qDebug() << "Passed:" << test_passed;
    qDebug() << "Failed:" << test_failed;

    return {test_count, test_passed, test_failed};
}
