# @TEST-DOC: Verify multi-question DNS logging when the reply precedes the query.

# Associate answers after the corresponding questions arrive.
# @TEST-EXEC: zeek -b -r $TRACES/dns/dns-reply-before-query.pcap base/protocols/dns
# @TEST-EXEC: zeek-cut query qtype_name answers < dns.log > split.log
# @TEST-EXEC: btest-diff split.log

# Fall back when the retained answer record limit is exceeded.
# @TEST-EXEC: zeek -b -r $TRACES/dns/dns-reply-before-query.pcap base/protocols/dns DNS::max_multi_question_answer_records=2
# @TEST-EXEC: zeek-cut query qtype_name answers < dns.log > fallback.log
# @TEST-EXEC: btest-diff fallback.log
