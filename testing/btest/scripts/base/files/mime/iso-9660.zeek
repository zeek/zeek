# @TEST-DOC: Test ISO 9660 mime detection works with increased default_file_bof_buffer_size.
#
# @TEST-EXEC: zcat <$TRACES/http/iso-download.pcap.gz | zeek -b -r - %INPUT
# @TEST-EXEC: zeek-cut -m fuid source mime_type filename < files.log > files.log.cut
# @TEST-EXEC: btest-diff files.log.cut

@load base/protocols/http
@load base/frameworks/files

redef default_file_bof_buffer_size = 40000;

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( f$source == "HTTP" )
		f$info$filename = split_string(c$http$uri, /\//)[-1];
	}
