# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: zeek -b ./pathtest.zeek >out2
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out2

print @DIR;

@TEST-START-FILE pathtest.zeek
print @DIR;
@TEST-END-FILE
