# @TEST-DOC: Set dpd_reassemble_first_packets=F, but expect reassembly to be enabled and the HTTP analyzer to work due to being registered for port 80.
# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff http.log

redef dpd_reassemble_first_packets = F;

@load base/protocols/conn
@load base/protocols/http
