@load base/frameworks/intel
@load base/protocols/smtp
@load base/utils/urls
@load ./where-locations

event intel_mime_data(f: fa_file, data: string)
	{
	if ( ! f?$conns )
		return;

	for ( cid, c in f$conns )
		{
		local urls = find_all_urls_without_scheme(data);
		for ( url in urls )
			{
			Intel::seen([$indicator=url,
			             $indicator_type=Intel::URL,
			             $conn=c,
			             $where=SMTP::IN_MESSAGE]);
			}
		}
	}

event file_new(f: fa_file)
	{
	if ( f$source == "SMTP" )
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=intel_mime_data]);
	}
