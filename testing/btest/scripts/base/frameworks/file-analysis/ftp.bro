# @TEST-EXEC: bro -r $TRACES/ftp/retr.trace %INPUT >out
# @TEST-EXEC: btest-diff out
# @TEST-EXEC: btest-diff thefile

global actions: set[FileAnalysis::ActionArgs];

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	{
	print trig;

	switch ( trig ) {
	case FileAnalysis::TRIGGER_NEW:
		print info$file_id, info$seen_bytes, info$missing_bytes;

		if ( info$source == "FTP_DATA" )
			{
			for ( act in actions )
				FileAnalysis::add_action(info$file_id, act);
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

event bro_init()
	{
	add actions[[$act=FileAnalysis::ACTION_EXTRACT,
	             $extract_filename="thefile"]];
	add actions[[$act=FileAnalysis::ACTION_MD5]];
	add actions[[$act=FileAnalysis::ACTION_SHA1]];
	add actions[[$act=FileAnalysis::ACTION_SHA256]];
	}
