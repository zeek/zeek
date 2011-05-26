##! This script can be used to extract either the originator's data or the 
##! responders data or both.  By default nothing is extracted, and in order 
##! to actually extract data the ``c$extract_orig`` and/or the
##! ``c$extract_resp`` variable must be set to T.  One way to achieve
##! would be to handle the connection_established event elsewhere and set the
##! extract_orig and extract_resp options there.
##! This script does not work well in a cluster context unless it has a remotely
##! mounted disk to write the content files to.
##!
##! .. note:: This script has a problem if another connection happens using the 
##!    same IP addresses and ports.  There is nothing in place to test for
##!    the existence of a file.

module Conn;

export {
	## The prefix given to files as they are opened on disk.
	const extraction_prefix = "contents" &redef;
	
	## If this variable is set to T, then all contents of all files will be 
	## extracted.
	const default_extract = F &redef;
}

redef record connection += {
	extract_orig: bool &default=default_extract;
	extract_resp: bool &default=default_extract;
};

event connection_established(c: connection) &priority=-5
	{
	local id = c$id;

	if ( c$extract_orig )
		{
		local orig_file = fmt("%s.%s.%s:%d-%s:%d.dat", 
		                      extraction_prefix, c$uid,
		                      id$orig_h, id$orig_p, id$resp_h, id$resp_p);
		local orig_f = open(orig_file);
		set_contents_file(id, CONTENTS_ORIG, orig_f);
		}
		
	if ( c$extract_resp )
		{
		local resp_file = fmt("%s.%s.%s:%d-%s:%d.dat", 
		                      extraction_prefix, c$uid,
		                      id$resp_h, id$resp_p, id$orig_h, id$orig_p);
		local resp_f = open(resp_file);
		set_contents_file(id, CONTENTS_RESP, resp_f);
		}
	}
