# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff files.log

@load base/protocols/http
@load base/files/hash
@load base/files/extract

event zeek_init()
	{
	Files::register_for_mime_type(Files::ANALYZER_MD5, "text/plain");
	};


