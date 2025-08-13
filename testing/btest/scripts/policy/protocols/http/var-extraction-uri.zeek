# @TEST-EXEC: zeek -r ${TRACES}/http/http-filename.pcap %INPUT
# @TEST-EXEC: zeek-cut uri uri_vars <http.log > http-reduced.log
# @TEST-EXEC: btest-diff http-reduced.log

@load policy/protocols/http/var-extraction-uri
