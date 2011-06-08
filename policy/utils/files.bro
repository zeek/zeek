
## This function can be used to generate a consistent filename for when
## contents of a file, stream, or connection are being extracted to disk.
function generate_extraction_filename(prefix: string, c: connection, suffix: string): string
	{
	local conn_info = fmt("%s:%d-%s:%d", 
	                      c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
	
	if ( prefix != "" )
		conn_info = fmt("%s_%s", prefix, conn_info);
	if ( suffix != "" )
		conn_info = fmt("%s_%s", conn_info, suffix);
		
	return conn_info;
	}