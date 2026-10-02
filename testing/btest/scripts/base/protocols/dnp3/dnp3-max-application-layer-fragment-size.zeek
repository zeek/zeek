# @TEST-DOC: Test the default DNP3::max_application_layer_fragment_size triggering a weird.
#
# @TEST-EXEC: gunzip -c $TRACES/dnp3/dnp3-response-object-count-amplification.pcap.gz | zeek -b -r - %INPUT >&2
#
# @TEST-EXEC: btest-diff-cut -m uid service history orig_pkts resp_pkts conn.log
# @TEST-EXEC: btest-diff-cut -m weird.log

@load base/protocols/conn
@load base/protocols/dnp3
@load base/frameworks/notice/weird
