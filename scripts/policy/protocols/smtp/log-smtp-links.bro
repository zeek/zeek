##! This script performs logging of the links found within files transferred
##! over smtp connections. 

@load base/protocols/smtp/main

module SMTP;

export {
	## Log to contain links within emails.
	redef enum Log::ID += { Links_LOG };
	
	## Holds information about SMTP Links to be written to the log.
	type LinkInfo: record {
		## When the email and link were seen.
		ts:	time	&log;
		## Connection Unique identifier.
		uid:	string	&log;
		## Connection details.
		id:	conn_id	&log;
		# Host portion of the URL.
		host:	string	&log &optional;
		# The full URL.
		url:	string	&log &optional;
	};

	## Event used for logging email links
	global log_link: event(rec: LinkInfo);

}

event bro_init() &priority=5
	{
	## Add the log stream to the logging framework.
	Log::create_stream(SMTP::Links_LOG, [$columns=LinkInfo, $ev=log_link]);
	}

## Used to split hostnames from URLs
function extract_host(url: string): string
        {
        local split_on_slash = split(url, /\//);
        return split_on_slash[1];
        }

## Function to write to the log for SMTP links
function log_smtp_url(c: connection, url: string)
	{
	## Set the fields within the link info record.
	local info: LinkInfo;
	info$ts = c$smtp$ts;
	info$uid = c$smtp$uid;
	info$id = c$id;
	info$host = extract_host(url);
	info$url = url;	
	
	## Write the log entry
	Log::write(SMTP::Links_LOG, info);
	}

## Streaming File Analysis event used to extract links from email bodies.
event extract_smtp_links(f: fa_file, data: string)
	{
	if ( ! f?$conns )
		return; 

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];
		local urls = find_all_urls_without_scheme(data);
		
		## Loop through each URL and log them.
		for ( url in urls )
			log_smtp_url(c, url);
		}
	}

## When a file comes in through SMTP, send the file to the extract_smtp_links
## streaming analyzer event to be examined to find any links in the file.
event file_new(f: fa_file)
	{
	if ( ! f?$source )
		return;
	
	## Attach the file analyzer to files sourced from SMTP.
	if ( f$source == "SMTP" )
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT,
					[$stream_event=extract_smtp_links]);
	}
