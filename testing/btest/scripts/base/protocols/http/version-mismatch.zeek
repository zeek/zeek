# @TEST-DOC: Pcap extracted from 2009-M57-day11-18.trace: The server replies with HTTP/1.1, then HTTP/1.0 (also different Server headers).
# @TEST-EXEC: zeek -b -Cr $TRACES/http/version-mismatch.pcap %INPUT
# @TEST-EXEC: btest-diff http.log
# @TEST-EXEC: btest-diff weird.log

@load base/protocols/http
@load base/frameworks/notice/weird
