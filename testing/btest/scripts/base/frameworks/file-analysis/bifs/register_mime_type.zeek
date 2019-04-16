# @TEST-EXEC: bro -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff files.log

event bro_init()
	{
	Files::register_for_mime_type(Files::ANALYZER_MD5, "text/plain");
	};


