@load base/frameworks/intel
@load base/protocols/http/utils
@load ./where-locations

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat) &group="Intel::URL"
	{
	if ( is_orig && c?$http )
		Intel::seen(Intel::Seen($indicator=HTTP::build_url(c$http),
		                        $indicator_type=Intel::URL,
		                        $conn=c,
		                        $where=HTTP::IN_URL));
	}
