
## This function can be used to generate a consistent filename for when
## 
function generate_extraction_filename(prefix: string, c: connection, suffix: string): string
	{
	local conn_info = fmt("%s:%d-%s:%d", 
	                      c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
	
	if ( prefix != "" )
		conn_info = fmt("%s_%s", prefix, conn_info);
	if ( suffix != "" )
		conn_info = fmt("%s_%s", conn_info, suffix);
	}
	
	contents_1.2.3.4:54321-4.3.2.1:80_resp.dat
	http-entity_1.2.3.4:54321-4.3.2.1:80_reply.dat
	