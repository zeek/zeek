@load base/frameworks/intel
@load base/utils/urls
@load ./where-locations

event mime_segment_data(c: connection, length: count, data: string) &priority=3
	{
	local urls = find_all_urls_without_scheme(data);
	for ( url in urls )
		{
		Intel::seen([$str=url,
		             $str_type=Intel::URL,
		             $conn=c,
		             $where=SMTP::IN_MESSAGE]);
		}
	}