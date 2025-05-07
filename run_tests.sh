#!/bin/bash

# Run tests using the existing test files

echo "Running CryptoScan tests..."

# First build the project to make sure it compiles
echo "Building project..."
go build -o cryptoscan

# Check build status
if [ $? -ne 0 ]; then
    echo "Build failed. Exiting..."
    exit 1
fi

echo "Build successful. Running tests..."

# Create a test summary file
TEST_SUMMARY="test_summary.txt"
echo "CryptoScan Test Summary" > $TEST_SUMMARY
echo "======================" >> $TEST_SUMMARY
echo "Date: $(date)" >> $TEST_SUMMARY
echo "" >> $TEST_SUMMARY

# Helper function to run tests for a specific package
run_package_tests() {
    local pkg=$1
    local pkg_name=$2
    
    echo -e "\nTesting $pkg_name package..."
    echo -e "\n--- $pkg_name Tests ---" >> $TEST_SUMMARY
    
    # Run tests without verbose mode to get a cleaner summary
    go test $pkg
    
    if [ $? -eq 0 ]; then
        echo "✅ $pkg_name tests passed" | tee -a $TEST_SUMMARY
    else
        echo "❌ $pkg_name tests failed" | tee -a $TEST_SUMMARY
    fi
}

# Run tests for each major package
run_package_tests "./pkg/utils" "Utils"
run_package_tests "./pkg/spinner" "Spinner"
run_package_tests "./pkg/types" "Types"
run_package_tests "./internal/scanner" "Scanner"
run_package_tests "./internal/reporter" "Reporter"
run_package_tests "./internal/git" "Git"
run_package_tests "./cmd" "Commands"

echo -e "\n--- Summary ---" >> $TEST_SUMMARY
echo "Tests completed at $(date)" >> $TEST_SUMMARY

echo -e "\nTest execution completed. Summary available in $TEST_SUMMARY"

# Display the summary
cat $TEST_SUMMARY

echo -e "\nDone."