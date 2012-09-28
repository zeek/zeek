@load base/frameworks/intel

export {
	redef enum Intel::Where += {
		HTTP::IN_HOST_HEADER,
	};
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
	if ( is_orig && name == "HOST" )
		Intel::seen([$str=value,
		             $str_type=Intel::DOMAIN,
		             $conn=c,
		             $where=HTTP::IN_HOST_HEADER]);
	}
