# @TEST-DOC: Smoke checking that nothing is obviously broken with ZAM.
#
# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: mkdir non-zam
# @TEST-EXEC: mv *log non-zam
#
# @TEST-EXEC: zeek -OZAM -r $TRACES/wikipedia.trace %INPUT
#
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff dns.log
# @TEST-EXEC: btest-diff http.log
#
# Compare the ZAM created logs with the non-zam ones
# @TEST-EXEC: TEST_BASELINE=./non-zam btest-diff conn.log
# @TEST-EXEC: TEST_BASELINE=./non-zam btest-diff dns.log
# @TEST-EXEC: TEST_BASELINE=./non-zam btest-diff http.log
