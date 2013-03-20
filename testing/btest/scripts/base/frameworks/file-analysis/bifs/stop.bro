# @TEST-EXEC: bro -r $TRACES/http/get.trace %INPUT >get.out
# @TEST-EXEC: btest-diff get.out
# @TEST-EXEC: test ! -s Cx92a0ym5R8-file

global actions: set[FileAnalysis::ActionArgs];

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	{
	print trig;

	switch ( trig ) {
	case FileAnalysis::TRIGGER_NEW:
		FileAnalysis::stop(info$file_id);

		print info$file_id, info$seen_bytes, info$missing_bytes;

		if ( info$source == "HTTP" )
			{
			for ( act in actions )
				FileAnalysis::add_action(info$file_id, act);
			local filename: string = fmt("%s-file", info$file_id);
			FileAnalysis::add_action(info$file_id,
			                         [$act=FileAnalysis::ACTION_EXTRACT,
			                          $extract_filename=filename]);
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
		print info$conn_uids;
		print info$conn_ids;

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

event bro_init()
	{
	add actions[[$act=FileAnalysis::ACTION_MD5]];
	add actions[[$act=FileAnalysis::ACTION_SHA1]];
	add actions[[$act=FileAnalysis::ACTION_SHA256]];
	}
