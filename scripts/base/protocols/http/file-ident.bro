##! Identification of file types in HTTP response bodies with file content sniffing.

@load base/frameworks/notice
@load ./main
@load ./utils
@load ./file-analysis

module HTTP;

export {
	redef enum Notice::Type += {
		## Indicates when the file extension doesn't seem to match the file contents.
		Incorrect_File_Type,
	};

	redef record Info += {
		## Mime type of response body identified by content sniffing.
		mime_type:    string   &log &optional;
	};
	
	## Mapping between mime types and regular expressions for URLs
	## The :bro:enum:`HTTP::Incorrect_File_Type` notice is generated if the pattern 
	## doesn't match the mime type that was discovered.
	const mime_types_extensions: table[string] of pattern = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
	
	## A pattern for filtering out :bro:enum:`HTTP::Incorrect_File_Type` urls
	## that are not noteworthy before a notice is created.  Each
	## pattern added should match the complete URL (the matched URLs include
	## "http://" at the beginning).
	const ignored_incorrect_file_type_urls = /^$/ &redef;
}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_TYPE ) return;
	if ( ! info?$mime_type ) return;
	if ( ! info?$source ) return;
	if ( info$source != "HTTP" ) return;
	if ( ! info?$conns ) return;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$http ) next;

		c$http$mime_type = info$mime_type;

		if ( info$mime_type !in mime_types_extensions ) next;
		if ( ! c$http?$uri ) next;
		if ( mime_types_extensions[info$mime_type] in c$http$uri ) next;

		local url = build_url_http(c$http);

		if ( url == ignored_incorrect_file_type_urls ) next;

		local message = fmt("%s %s %s", info$mime_type, c$http$method, url);
		NOTICE([$note=Incorrect_File_Type,
		        $msg=message,
		        $conn=c]);
		}
	}
