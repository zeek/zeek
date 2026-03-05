#
# @TEST-EXEC: zeek -b -C -r $TRACES/www-odd-url.pcap base/protocols/http
# @TEST-EXEC: btest-diff http.log

