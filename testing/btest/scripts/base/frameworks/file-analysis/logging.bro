# @TEST-EXEC: bro -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff file_analysis.log

global actions: set[FileAnalysis::ActionArgs];

event file_chunk(info: FileAnalysis::Info, data: string, off: count)
	{
	print "file_chunk", info$file_id, |data|, off, data;
	}

event file_stream(info: FileAnalysis::Info, data: string)
	{
	print "file_stream", info$file_id, |data|, data;
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	{
	print trig;

	switch ( trig ) {
	case FileAnalysis::TRIGGER_NEW:
		print info$file_id, info$seen_bytes, info$missing_bytes;

		if ( info$source == "HTTP" )
			{
			for ( act in actions )
				FileAnalysis::add_action(info$file_id, act);
			local filename: string = fmt("%s-file", info$file_id);
			FileAnalysis::add_action(info$file_id,
			                         [$act=FileAnalysis::ACTION_EXTRACT,
			                          $extract_filename=filename]);
			FileAnalysis::add_action(info$file_id,
			                         [$act=FileAnalysis::ACTION_DATA_EVENT,
			                          $chunk_event=file_chunk,
			                          $stream_event=file_stream]);

			}
		break;

	case FileAnalysis::TRIGGER_BOF_BUFFER:
		if ( info?$bof_buffer )
			print info$bof_buffer[0:10];
		break;

	case FileAnalysis::TRIGGER_TYPE:
		# not actually printing the values due to libmagic variances
		if ( info?$file_type )
			print "file type is set";
		if ( info?$mime_type )
			print "mime type is set";
		break;

	case FileAnalysis::TRIGGER_EOF:
		fallthrough;
	case FileAnalysis::TRIGGER_DONE:

		print info$file_id, info$seen_bytes, info$missing_bytes;
		if ( info?$conns )
			for ( cid in info$conns )
				print cid;

		if ( info?$total_bytes )
			print "total bytes: " + fmt("%s", info$total_bytes);
		if ( info?$source )
			print "source: " + info$source;

		for ( act in info$actions )
			switch ( act$act ) {
			case FileAnalysis::ACTION_MD5:
				print fmt("MD5: %s", info$actions[act]$md5);
				break;
			case FileAnalysis::ACTION_SHA1:
				print fmt("SHA1: %s", info$actions[act]$sha1);
				break;
			case FileAnalysis::ACTION_SHA256:
				print fmt("SHA256: %s", info$actions[act]$sha256);
				break;
			}
		break;
	}
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=-5
	{
	if ( trig != FileAnalysis::TRIGGER_TYPE ) return;

	# avoids libmagic variances across systems
	if ( info?$mime_type )
		info$mime_type = "set";
	if ( info?$file_type )
		info$file_type = "set";
	}

event bro_init()
	{
	add actions[[$act=FileAnalysis::ACTION_MD5]];
	add actions[[$act=FileAnalysis::ACTION_SHA1]];
	add actions[[$act=FileAnalysis::ACTION_SHA256]];
	}
