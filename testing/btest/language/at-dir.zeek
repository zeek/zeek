# Can't use this test for -O gen-C++ because the additional script doesn't
# have testing/btest in its path when loaded, so isn't recognized for
# compilation.
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: zeek -b ./pathtest.zeek >out2
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out2

print @DIR;

# @TEST-START-FILE pathtest.zeek
print @DIR;
# @TEST-END-FILE
