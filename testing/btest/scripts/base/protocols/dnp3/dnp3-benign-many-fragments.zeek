# @TEST-DOC: DNP3 connection with many small application fragments must not trip the fragment-size cap.
#
# @TEST-EXEC: gunzip -c $TRACES/dnp3/dnp3-benign-many-fragments.pcap.gz | zeek -b -r - %INPUT >&2
#
# @TEST-EXEC: btest-diff-cut -m uid service history orig_pkts resp_pkts conn.log
# @TEST-EXEC: ! test -f weird.log

redef DNP3::max_application_layer_fragment_size = 2 * 1024;

@load base/protocols/conn
@load base/protocols/dnp3
@load base/frameworks/notice/weird
