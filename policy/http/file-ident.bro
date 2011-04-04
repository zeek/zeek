##! This script is involved in the identification of file types in HTTP
##! response bodies.

# TODO: 
#  * Add a filter for configurably extracting certain file types into their own log?

@load http/base

@load notice
@load signatures

module HTTP;

redef enum Notice::Type += {
	# This notice is thrown when the file extension doesn't 
	# seem to match the file contents.
	HTTP_IncorrectFileType,
};

export {
	redef enum Tag += {
		IDENTIFIED_FILE
	};
	
	redef record State += {
		## This will record the mime_type identified.
		mime_type:    string   &log &optional;
	};
	
	# Since we're looking into the body for the mimetype detection, logging
	# *can't* take place until after the body.  To account for short bodies 
	# that may be contained within a single packet, we will wait until the 
	# next request because the http_entity_done event currently fires before 
	# HTTP body content matching signatures.
	# TODO: should there be another log point for "after X body bytes"?
	redef default_log_point = BEFORE_NEXT_REQUEST;
	
	# MIME types that you'd like this script to identify and log.
	const watched_mime_types = /application\/x-dosexec/
	                         | /application\/x-executable/ &redef;
	
	# TODO This may be better done with a filter.
	# URLs included here are not logged and notices are not thrown.
	# Take care when defining regexes to not be overly broad.
	#const ignored_uris = /^http:\/\/(au\.|www\.)?download\.windowsupdate\.com\/msdownload\/update/ &redef;
	
	# Create regexes that *should* in be in the urls for specifics mime types.
	# Notices are thrown if the pattern doesn't match the url for the file type.
	const mime_types_extensions: table[string] of pattern = {
		["application/x-dosexec"] = /\.([eE][xX][eE]|[dD][lL][lL])/,
	} &redef;
}

redef signature_files += "http/file-ident.sig";
# Ignore the signatures used to match files
redef Signatures::ignored_ids += /^matchfile-/;

event signature_match(state: signature_state, msg: string, data: string) &priority=5
	{
	# Only signatures matching file types are dealt with here.
	if ( /^matchfile/ !in state$sig_id ) return;
	
	local c = state$conn;
	
	# Not much point in any of this if we don't know about the HTTP session.
	if ( ! c?$http ) return;
	
	# Set the mime type that was detected.
	c$http$mime_type = msg;
	
	if ( msg in mime_types_extensions && 
	     mime_types_extensions[msg] !in c$http$uri )
		{
		local message = fmt("%s %s %s %s", msg, c$http$method, c$http$host, c$http$uri);
		NOTICE([$note=HTTP_IncorrectFileType,
		        $msg=message,
		        $conn=c,
		        $method=c$http$method,
		        $URL=c$http$uri]);
		}
	}
