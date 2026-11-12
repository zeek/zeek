# @TEST-DOC: Verify that multi-question DNS logging handles the answer record limit of 50.

# @TEST-EXEC: zeek -b -r $TRACES/dns/dns-answer-limit-boundary.pcap base/protocols/dns
# @TEST-EXEC: zeek-cut trans_id query qtype_name answers < dns.log | awk -F '\t' '{ print $1, $2, $3, split($4, a, ",") }' > out
# @TEST-EXEC: btest-diff out
