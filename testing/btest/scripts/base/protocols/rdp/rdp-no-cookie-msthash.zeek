# Test a trace that does not have a cookie field.

# @TEST-EXEC: zeek -b -r $TRACES/rdp/rdp-no-cookie-mstshash.pcap %INPUT
# @TEST-EXEC: btest-diff rdp.log
# @TEST-EXEC: btest-diff ssl.log
# @TEST-EXEC: test ! -f analyzer.log

@load base/protocols/rdp
@load base/protocols/ssl

redef SSL::log_include_server_certificate_subject_issuer=T;
