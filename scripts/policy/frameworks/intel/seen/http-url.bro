@load base/frameworks/intel
@load base/protocols/http/utils
@load ./where-locations

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( is_orig && c?$http )
		{
		# www_strip converts www.domain.com to domain.com for easier intel matching
		local www_strip = split_string1(c$http$host, /\./);
		if ( www_strip[0] == /www/ )
                	Intel::seen([$indicator=www_strip[1],
                                     $indicator_type=Intel::URL,
                                     $conn=c,
                                     $where=HTTP::IN_URL]);
                else
		Intel::seen([$indicator=HTTP::build_url(c$http),
		             $indicator_type=Intel::URL,
		             $conn=c,
		             $where=HTTP::IN_URL]);
		}
	}
