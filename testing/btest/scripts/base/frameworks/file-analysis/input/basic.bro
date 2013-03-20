# @TEST-EXEC: btest-bg-run bro bro -b %INPUT
# @TEST-EXEC: btest-bg-wait 8
# @TEST-EXEC: btest-diff bro/.stdout
# @TEST-EXEC: diff -q bro/nYgPNGLrZf9-file input.log

redef exit_only_after_terminate = T;

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	e	c	p	sn	a	d	t	iv	s	sc	ss	se	vc	ve	ns
#types	bool	int	enum	count	port	subnet	addr	double	time	interval	string	table	table	table	vector	vector	string
T	-42	SSH::LOG	21	123	10.0.0.0/24	1.2.3.4	3.14	1315801931.273616	100.000000	hurz	2,4,1,3	CC,AA,BB	EMPTY	10,20,30	EMPTY	4242
@TEST-END-FILE

module A;

type Val: record {
	s: string;
};

event line(description: Input::EventDescription, tpe: Input::Event, s: string)
	{
	FileAnalysis::data_stream(description$source, s);
	}

event Input::end_of_data(name: string, source: string) 
	{
	FileAnalysis::eof(source);
	}

event bro_init()
	{
	Input::add_event([$source="../input.log", $reader=Input::READER_BINARY,
	                  $mode=Input::MANUAL, $name="input", $fields=Val,
	                  $ev=line, $want_record=F]);
	Input::remove("input");
	}

global actions: set[FileAnalysis::ActionArgs];

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	{
	local filename: string;
	print trig;

	switch ( trig ) {
	case FileAnalysis::TRIGGER_NEW:

		print info$file_id, info$seen_bytes, info$missing_bytes;

		for ( act in actions )
			FileAnalysis::add_action(info$file_id, act);
		filename = fmt("%s-file", info$file_id);
		FileAnalysis::add_action(info$file_id,
		                         [$act=FileAnalysis::ACTION_EXTRACT,
		                          $extract_filename=filename]);
		break;

	case FileAnalysis::TRIGGER_BOF_BUFFER:
		if ( info?$bof_buffer )
			print info$bof_buffer[0:10];
		break;

	case FileAnalysis::TRIGGER_TYPE:
		for ( act in actions )
			FileAnalysis::remove_action(info$file_id, act);
		filename = fmt("%s-file", info$file_id);
		FileAnalysis::remove_action(info$file_id,
			                         [$act=FileAnalysis::ACTION_EXTRACT,
			                          $extract_filename=filename]);
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

		if ( info?$total_bytes )
			print "total bytes: " + fmt("%s", info$total_bytes);
		if ( info?$source )
			print "source: " + info$source;

		for ( act in info$actions )
			switch ( act$act ) {
			case FileAnalysis::ACTION_MD5:
				if ( info$actions[act]?$md5 )
					print fmt("MD5: %s", info$actions[act]$md5);
				break;
			case FileAnalysis::ACTION_SHA1:
				if ( info$actions[act]?$sha1 )
					print fmt("SHA1: %s", info$actions[act]$sha1);
				break;
			case FileAnalysis::ACTION_SHA256:
				if ( info$actions[act]?$sha256 )
					print fmt("SHA256: %s", info$actions[act]$sha256);
				break;
			}
		terminate();
		break;
	}
	}

event bro_init()
	{
	add actions[[$act=FileAnalysis::ACTION_MD5]];
	add actions[[$act=FileAnalysis::ACTION_SHA1]];
	add actions[[$act=FileAnalysis::ACTION_SHA256]];
	}
