# Extracts the items from HTTP traffic, one per file.
# Files are named:
#
#    <prefix>.<n>.<orig-addr>_<orig-port>.<resp-addr>_<resp-port>.<is-orig>
#
# where <prefix> is a redef'able prefix (default: "http-item"), <n> is
# a number uniquely identifying the item, the next four are describe
# the connection tuple, and <is-orig> is "orig" if the item was transferred
# from the originator to the responder, "resp" otherwise.

@load http/file-ident

module HTTP;

export {
	## Pattern of file mime types to extract from HTTP entity bodies.
	const extract_file_types = /NO_DEFAULT/ &redef;

	## The on-disk prefix for files to be extracted from HTTP entity bodies.
	const extraction_prefix = "http-item" &redef;
}

redef record State += {
	# TODO: this will go away once file types can be sent to the logging framework.
	extracted_filename:  string &optional &log;
	
	## This field can be set per-connection to determine if the entity body
	## will be extracted.  It must be set to T on or before the first 
	## entity_body_data event.
	extract_file:        bool &default=F;
	extracted_file:      file &optional;
};

## Mark files to be extracted if they were identified as a mime type matched 
## by the extract_file_types variable and they aren't being extracted yet.
event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=6
	{
	if ( ! c$http$extract_file &&
	     c$http?$mime_type &&
		 extract_file_types in c$http$mime_type )
		c$http$extract_file = T;
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=5
	{
	if ( ! c$http$extract_file )
		return;
		
	# Open a file handle if this file hasn't seen any data yet.
	if ( ! c$http?$extracted_file )
		{
		local id = c$id;
		local fname = fmt("%s.%d.%s_%d.%s_%d.%s",
					extraction_prefix, c$http_entity_bodies,
					id$orig_h, id$orig_p,
					id$resp_h, id$resp_p,
					is_orig ? "orig" : "resp");
		# TODO: removed once the extract_file field can be logged.
		c$http$extracted_filename = fname;
		c$http$extracted_file = open(fname);
		# TODO: is the problem with NULL bytes and raw_output still there?
		enable_raw_output(c$http$extracted_file);
		}
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=-5
	{
	if ( c$http?$extracted_file )
		print c$http$extracted_file, data;
	}