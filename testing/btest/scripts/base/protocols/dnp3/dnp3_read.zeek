#
# @TEST-EXEC: zeek -r $TRACES/dnp3/dnp3_read.pcap %DIR/events.zeek >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: cat output | awk '{print $1}' | sort | uniq | wc -l >covered
# @TEST-EXEC: cat ${DIST}/src/analyzer/protocol/dnp3/events.bif  | grep "^event dnp3_" | wc -l >total
# @TEST-EXEC: echo `cat covered` of `cat total` events triggered by trace >coverage
# @TEST-EXEC: btest-diff coverage
# @TEST-EXEC: btest-diff dnp3.log
#
