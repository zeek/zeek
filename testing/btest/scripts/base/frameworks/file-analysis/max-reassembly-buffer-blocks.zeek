# @TEST-DOC: Test the Files::reassembly_buffer_blocks setting with a HTTP Content-Range trace that transports 20 blocks.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/file-reassembly-odd-offset-ranges.pcap %INPUT >out
#
# @TEST-EXEC: btest-diff-cut -m uid service history conn.log
# @TEST-EXEC: btest-diff-cut -m fuid uid total_bytes seen_bytes missing_bytes overflow_bytes files.log
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load base/protocols/http
@load base/frameworks/files

# The transfer has 20 non-contiguous blocks. Set the limit to 5 to trigger 3 overflows.
redef Files::reassembly_buffer_blocks = 5;

event file_gap(f: fa_file, offset: count, len: count)
	{
	print "file_gap", f$id, offset, len;
	}

event file_reassembly_overflow(f: fa_file, offset: count, skipped: count)
	{
	# This is strange. skipped seems to hold the value of the first
	# gap only. Not all gaps.gap This must be pre-existing. If you fix
	# something here and the resulting baseline changes, that's probably good.
	print "file_reassembly_overflow", f$id, offset, skipped;
	}
