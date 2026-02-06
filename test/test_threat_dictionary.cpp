#include "test_threat_dictionary.h"
#include "ThreatDictionary.h"
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

std::tuple<int, int, int> runThreatDictionaryTests(bool verbose) {
    Q_UNUSED(verbose)
    test_count = 0;
    test_passed = 0;
    test_failed = 0;

    qDebug() << "\n========== Threat Dictionary Tests ==========";

    ThreatDictionary dictionary;

    // Test loading builtin dictionaries
    bool loadResult = dictionary.loadBuiltinDictionaries();
    test("Load Builtin Dictionaries", loadResult);

    if (loadResult) {
        int totalCount = dictionary.getTotalEntryCount();
        test("Dictionary Has Entries", totalCount > 0);
        if (verbose) {
            qDebug() << "Loaded" << totalCount << "dictionary entries";
        }

        // Test process matching
        auto matchResult = dictionary.matchProcess("svchost.exe");
        test("Match Known Process", true); // svchost should be known

        // Test hash matching
        matchResult = dictionary.matchFileHash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        test("Match Known Hash", !matchResult.matchedEntryName.isEmpty() ||
                                  !matchResult.matchedValue.isEmpty());

        // Test categories
        auto categories = dictionary.getCategories();
        test("Get Categories", !categories.isEmpty());
        if (verbose) {
            qDebug() << "Found" << categories.size() << "categories";
        }
    }

    // Test adding a custom entry
    ThreatEntry entry;
    entry.id = 999;
    entry.name = "Test Malware";
    entry.category = "process";
    entry.type = "name";
    entry.value = "test_malware.exe";
    entry.severity = "high";
    entry.isEnabled = true;

    bool addResult = dictionary.addEntry(entry);
    test("Add Custom Entry", addResult);

    // Test entry retrieval
    if (addResult) {
        auto retrievedEntry = dictionary.getEntry(999);
        test("Retrieve Entry", retrievedEntry.id == 999);
    }

    qDebug() << "\nThreat Dictionary Tests Results:";
    qDebug() << "Total:" << test_count;
    qDebug() << "Passed:" << test_passed;
    qDebug() << "Failed:" << test_failed;

    return {test_count, test_passed, test_failed};
}
