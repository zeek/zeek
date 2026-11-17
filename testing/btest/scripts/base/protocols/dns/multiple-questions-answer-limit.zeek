# @TEST-DOC: Verify that multi-question DNS logging falls back when the answer record limit is exceeded.

# Exactly at the limit: split into separate question logs.
# @TEST-EXEC: zeek -b -r $TRACES/dns/dns-shared-cname.pcap base/protocols/dns DNS::max_multi_question_answer_records=3
# @TEST-EXEC: mv dns.log dns-within-limit.log
# @TEST-EXEC: btest-diff dns-within-limit.log

# Above the limit: preserve the original single-entry logging behavior.
# @TEST-EXEC: zeek -b -r $TRACES/dns/dns-shared-cname.pcap base/protocols/dns DNS::max_multi_question_answer_records=2
# @TEST-EXEC: mv dns.log dns-over-limit.log
# @TEST-EXEC: btest-diff dns-over-limit.log
