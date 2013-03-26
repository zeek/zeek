@load base/frameworks/intel
@load base/protocols/smtp/file-analysis
@load base/utils/urls
@load ./where-locations

event intel_mime_data(info: FileAnalysis::Info, data: string)
	{
	if ( ! info?$conns ) return;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];
		local urls = find_all_urls_without_scheme(data);
		for ( url in urls )
			{
			Intel::seen([$str=url,
			             $str_type=Intel::URL,
			             $conn=c,
			             $where=SMTP::IN_MESSAGE]);
			}
		}
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_NEW ) return;
	if ( ! info?$source ) return;
	if ( info$source != "SMTP" ) return;

	FileAnalysis::add_action(info$file_id,
	                         [$act=FileAnalysis::ACTION_DATA_EVENT,
	                          $stream_event=intel_mime_data]);
	}
