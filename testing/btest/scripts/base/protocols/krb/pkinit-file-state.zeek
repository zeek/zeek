# @TEST-DOC: Test limiting the number of pa-data entries in a connection
# @TEST-EXEC: zeek -b -r $TRACES/krb/pkinit-file-state.pcap %INPUT
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/frameworks/notice/weird
@load base/protocols/krb

redef KRB::max_pa_data_records = 5;
