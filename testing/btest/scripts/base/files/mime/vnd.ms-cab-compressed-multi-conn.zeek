# @TEST-DOC: Increasing default_file_bof_buffer_size has subtle impact on mime_type detection and association for partial file transfers over HTTP. Test mainly to aid understanding.
#
# @TEST-EXEC: zeek -b -r $TRACES/http/vnd.ms-cab-compressed-multi-conn.pcap %INPUT
# @TEST-EXEC: zeek-cut -m fuid source mime_type filename < files.log > files.log.cut
# @TEST-EXEC: btest-diff files.log.cut
# @TEST-EXEC: zeek-cut -m uid method host status_code resp_fuids response_body_len resp_mime_types < http.log > http.log.cut
# @TEST-EXEC: btest-diff http.log.cut

@load base/protocols/http
@load base/frameworks/files

# Increases default_file_bof_buffer_size, resulting in only one of the GET
# of http.log having the application/vnd.ms-cab-compressed associated.
@load policy/frameworks/signatures/iso-9660

redef LogAscii::use_json = F;

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( f$source == "HTTP" )
		f$info$filename = split_string(c$http$uri, /\//)[-1];
	}
