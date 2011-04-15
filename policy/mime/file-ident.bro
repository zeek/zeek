module MIME;

export {
	## The default setting for finding mime types on files.
	const default_find_type = F &redef;

	redef record Info += {
		find_type:        bool    &default=default_find_type;
		
		mime_type:        string  &log &optional;
		mime_desc:        string  &log &optional;
	}
}

event mime_segment_data(c: connection, length: count, data: string) &priority=5
	{
	if ( c$mime$content_len == 0 )
		{
		c$mime$mime_type = identify_data(data, T);
		c$mime$mime_desc = identify_data(data, F);
		}
	}
