# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# @TEST-EXEC: bro -b ./pathtest.bro >out2
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out2

print @DIR;

@TEST-START-FILE pathtest.bro
print @DIR;
@TEST-END-FILE
