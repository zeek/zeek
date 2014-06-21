@load base/files/extract
@load base/files/hash

redef FileExtract::prefix = "./";

global test_file_analysis_source: string = "" &redef;

global test_file_analyzers: set[Files::Tag];

global test_get_file_name: function(f: fa_file): string =
	function(f: fa_file): string { return ""; } &redef;

global test_print_file_data_events: bool = F &redef;

global file_count: count = 0;

global file_map: table[string] of count;

function canonical_file_name(f: fa_file): string
	{
	return fmt("file #%d", file_map[f$id]);
	}

event file_chunk(f: fa_file, data: string, off: count)
	{
	if ( test_print_file_data_events )
		print "file_chunk", canonical_file_name(f), |data|, off, data;
	}

event file_stream(f: fa_file, data: string)
	{
	if ( test_print_file_data_events )
		print "file_stream", canonical_file_name(f), |data|, data;
	}

event file_new(f: fa_file)
	{
	print "FILE_NEW";

	file_map[f$id] = file_count;
	++file_count;

	print canonical_file_name(f), f$seen_bytes, f$missing_bytes;

	if ( test_file_analysis_source == "" ||
	     f$source == test_file_analysis_source )
		{
		for ( tag in test_file_analyzers )
			Files::add_analyzer(f, tag);

		local filename: string = test_get_file_name(f);
		if ( filename != "" )
			Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
			                       [$extract_filename=filename]);
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT,
		                       [$chunk_event=file_chunk,
		                        $stream_event=file_stream]);
		}

	if ( f?$bof_buffer )
		{
		print "FILE_BOF_BUFFER";
		print f$bof_buffer[0:11];
		}

	if ( f?$mime_type )
		{
		print "MIME_TYPE";
		print f$mime_type;
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	print "FILE_OVER_NEW_CONNECTION";
	}

event file_timeout(f: fa_file)
	{
	print "FILE_TIMEOUT";
	}

event file_gap(f: fa_file, offset: count, len: count)
	{
	print "FILE_GAP";
	}

event file_state_remove(f: fa_file)
	{
	print "FILE_STATE_REMOVE";
	print canonical_file_name(f), f$seen_bytes, f$missing_bytes;
	if ( f?$conns )
		for ( cid in f$conns )
			print cid;

	if ( f?$total_bytes )
		print "total bytes: " + fmt("%s", f$total_bytes);
	if ( f?$source )
		print "source: " + f$source;

	if ( ! f?$info ) return;

	if ( f$info?$md5 )
		print fmt("MD5: %s", f$info$md5);
	if ( f$info?$sha1 )
		print fmt("SHA1: %s", f$info$sha1);
	if ( f$info?$sha256 )
		print fmt("SHA256: %s", f$info$sha256);
	}

event bro_init()
	{
	add test_file_analyzers[Files::ANALYZER_MD5];
	add test_file_analyzers[Files::ANALYZER_SHA1];
	add test_file_analyzers[Files::ANALYZER_SHA256];
	}
