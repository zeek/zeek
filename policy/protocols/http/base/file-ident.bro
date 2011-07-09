##! This script is involved in the identification of file types in HTTP
##! response bodies.

@load http/base
@load http/utils

@load notice
@load signatures

redef signature_files += "protocols/http/file-ident.sig";
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
		
		## This indicates that no data of the current file transfer has been
		## seen yet.  After the first :bro:id:`http_entity_data` event, it 
		## will be set to T.
		first_chunk:     bool &default=T;
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
	
	if ( msg in mime_types_extensions && 
	     c$http?$uri && mime_types_extensions[msg] !in c$http$uri )
		{
		local url = build_url_http(c$http);
		local message = fmt("%s %s %s", msg, c$http$method, url);
		NOTICE([$note=IncorrectFileType,
		        $msg=message,
		        $conn=c,
		        $method=c$http$method,
		        $URL=url]);
		}
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=5
	{
	if ( c$http$first_chunk && ! c$http?$mime_type )
			c$http$mime_type = split1(identify_data(data, T), /;/)[1];
	}
	
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=-10
	{
	if ( c$http$first_chunk )
		c$http$first_chunk=F;
	}