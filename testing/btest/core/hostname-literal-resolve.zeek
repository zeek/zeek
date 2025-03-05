# @TEST-DOC: Testing deprecated hostname literal resolutions
#
# @TEST-EXEC: zeek --parse-only -b %INPUT 2>err.parse-only >out.parse-only
# @TEST-EXEC: zeek -b %INPUT 2>err >out
#
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err.parse-only
# @TEST-EXEC: btest-diff out.parse-only
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff err
# @TEST-EXEC: btest-diff out

print "dns.example.com", dns.example.com;
