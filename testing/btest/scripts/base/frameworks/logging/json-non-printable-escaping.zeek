# @TEST-DOC: Tests that non-printable characters are turned into the proper form for JSON
#
# @TEST-EXEC: zeek -C -b -r $TRACES/http/http-non-printable-characters.pcap %INPUT
# @TEST-EXEC: mv http.log http.log.tsv
# @TEST-EXEC: zeek -C -b -r $TRACES/http/http-non-printable-characters.pcap %INPUT LogAscii::use_json=T
# @TEST-EXEC: mv http.log http.log.json
# @TEST-EXEC: btest-diff http.log.tsv
# @TEST-EXEC: btest-diff http.log.json

@load base/protocols/conn
@load base/protocols/http
