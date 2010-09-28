# $Id: http-event.bro 6 2004-04-30 00:31:26Z jason $

@load http

module HTTP;

event http_event(c: connection, event_type: string, detail: string)
	{
	print http_log, fmt("%.6f %s HTTP event: [%s] \"%s\"",
				network_time(), id_string(c$id),
				event_type, detail);
	}
