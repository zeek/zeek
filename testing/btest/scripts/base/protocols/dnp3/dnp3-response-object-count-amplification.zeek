# @TEST-DOC: Verify DNP3 with the dnp3-response-object-count-amplification PCAP uses less than 1G of memory.
#
# Inflated memory usage under ASAN.
# @TEST-REQUIRES: ! have-asan
# @TEST-EXEC: zcat $TRACES/dnp3/dnp3-response-object-count-amplification.pcap.gz | zeek -b -r - %INPUT >&2
#
# @TEST-EXEC: btest-diff-cut -m uid service history orig_pkts resp_pkts conn.log

@load base/protocols/conn
@load base/protocols/dnp3

# This limit stops reaching the parser, disable it.
redef DNP3::max_application_layer_fragment_size = 0;

event zeek_done()
	{
	local proc_stats = get_proc_stats();
	local mem_mb = proc_stats$mem / 1024.0 / 1024.0;
	print "mem_mb", mem_mb;
	if ( mem_mb > 1024.0 )
		{
		print "USING TOO MUCH MEMORY", mem_mb;
		exit(1);
		}
	}
