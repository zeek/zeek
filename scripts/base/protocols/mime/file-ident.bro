@load ./main

module MIME;

export {
	redef record Info += {
		## Sniffed MIME type for the transfer.
		mime_type:        string  &log &optional;
	};
}

event mime_segment_data(c: connection, length: count, data: string) &priority=7
	{
	if ( c$mime$content_len == 0 )
		c$mime$mime_type = split1(identify_data(data, T), /;/)[1];
	}
