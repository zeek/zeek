##! This script is involved in the identification of file types in HTTP
##! response bodies.

@load http/base
@load http/utils

@load notice
@load signatures

redef signature_files += "http/file-ident.sig";
# Ignore the signatures used to match files
redef Signatures::ignored_ids += /^matchfile-/;

module HTTP;

export {
	redef enum Notice::Type += {
		# This notice is thrown when the file extension doesn't 
		# seem to match the file contents.
		IncorrectFileType,
	};

	redef record Info += {
		## This will record the mime_type identified.
		mime_type:    string   &log &optional;
	};

	redef enum Tags += {
		IDENTIFIED_FILE
	};
	
	# Create regexes that *should* in be in the urls for specifics mime types.
	# Notices are thrown if the pattern doesn't match the url for the file type.
	const mime_types_extensions: table[string] of pattern = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
}

event signature_match(state: signature_state, msg: string, data: string) &priority=5
	{
	# Only signatures matching file types are dealt with here.
	if ( /^matchfile-/ !in state$sig_id ) return;

	local c = state$conn;
	set_state(c, F, F);
	
	# Not much point in any of this if we don't know about the HTTP session.
	if ( ! c?$http ) return;
	
	# Set the mime type that was detected.
	c$http$mime_type = msg;
	
	# Fire the file_transferred event so that it can be picked up by other
	# scripts, like the http/file-hash script since that uses file type to
	# conditionally calculate an MD5 sum.
	# TODO: We are leaving the descr field blank for now, but it shouldn't 
	#       matter too much and hopefully the more generic file analysis code
	#       will make this completely irrelevant.
	event file_transferred(c, data, "", msg);
	
	if ( msg in mime_types_extensions && 
	     c$http?$uri && mime_types_extensions[msg] !in c$http$uri )
		{
		local url = build_url(c$http);
		local message = fmt("%s %s %s", msg, c$http$method, url);
		NOTICE([$note=IncorrectFileType,
		        $msg=message,
		        $conn=c,
		        $method=c$http$method,
		        $URL=url]);
		}
	}
