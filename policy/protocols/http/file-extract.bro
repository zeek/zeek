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

redef record Info += {
	## This field can be set per-connection to determine if the entity body
	## will be extracted.  It must be set to T on or before the first 
	## entity_body_data event.
	extract_file:        bool &default=F;
	
	## This is the holder for the file handle as the file is being written
	## to disk.
	extraction_file:      file &log &optional;
};

redef record State += {
	entity_bodies:       count &optional;
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
	if ( ! c$http?$extraction_file )
		{
		local suffix = fmt("_%s_%d.dat", is_orig ? "orig" : "resp", c$http_state$entity_bodies);
		local fname = generate_extraction_filename(extraction_prefix, c, suffix);
		
		c$http$extraction_file = open(fname);
		enable_raw_output(c$http$extraction_file);
		}
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=-5
	{
	if ( c$http?$extraction_file )
		print c$http$extraction_file, data;
	}