# @TEST-EXEC: zeek -r $TRACES/ftp/bigtransfer.pcap %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff files.log
# @TEST-EXEC: btest-diff conn.log

# The pcap has been truncated on purpose, so there's going to be large
# gaps that are there by design and shouldn't trigger the "skip
# deliveries" code paths because this test still needs to know about the
# payloads being delivered around critical boundaries (e.g. 32-bit TCP
# sequence wraparound and 32-bit data offsets).
redef tcp_excessive_data_without_further_acks=0;

event file_chunk(f: fa_file, data: string, off: count)
	{
	print "file_chunk", |data|, off, data;
	}

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT,
	                    [$chunk_event=file_chunk]);
	}
