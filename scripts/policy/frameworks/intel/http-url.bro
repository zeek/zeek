@load base/frameworks/intel
@load base/protocols/http/utils
@load ./where-locations

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( is_orig && c?$http )
		Intel::seen([$str=HTTP::build_url(c$http),
		             $str_type=Intel::URL,
		             $conn=c,
		             $where=HTTP::IN_URL]);
	}
