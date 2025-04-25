# This tests whether the HTTP analyzer handles HTTP keyword in lower case correctly or not.
#
# @TEST-EXEC: zeek -C -b -r $TRACES/http/http-lower-case.pcap %INPUT
# @TEST-EXEC: ! test -f dpd.log
# @TEST-EXEC: ! test -f analyzer.log
# @TEST-EXEC: zeek-cut uid name < weird.log > weird.log.standard
# @TEST-EXEC: btest-diff weird.log.standard
# @TEST-EXEC: mv http.log http.log.standard
# @TEST-EXEC: btest-diff http.log.standard

# @TEST-EXEC: rm *.log

# @TEST-EXEC: zeek -C -b -r $TRACES/http/http-lower-case-nonstandard-port.pcap %INPUT
# @TEST-EXEC: ! test -f dpd.log
# @TEST-EXEC: ! test -f analyzer.log
# @TEST-EXEC: zeek-cut uid name < weird.log > weird.log.nonstandard
# @TEST-EXEC: btest-diff weird.log.nonstandard
# @TEST-EXEC: mv http.log http.log.nonstandard
# @TEST-EXEC: btest-diff http.log.nonstandard

@load base/protocols/http
