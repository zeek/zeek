##! The mime script does analysis of MIME encoded messages seen in certain
##! protocols (only SMTP and POP3 at the moment).

@load utils/strings

module MIME;

export {
	redef enum Log::ID += { MIME };

	# Let's assume for now that nothing transferring files using 
	# MIME attachments is multiplexing for simplicity's sake.
	#   We can make the assumption that one connection == one file (at a time)
	
	type Info: record {
		## This is the timestamp of when the MIME content transfer began.
		ts:               time    &log;
		uid:              string  &log;
		id:               conn_id &log;
		## The application layer protocol over which the transfer was seen.
		app_protocol:     string  &log &optional;
		## The filename seen in the Content-Disposition header.
		filename:         string  &log &optional;
		## Track how many byte of the MIME encoded file have been seen.
		content_len:      count   &log &default=0;
	};
	
	type State: record {
		## Track the number of MIME encoded files transferred during this session.
		level:            count   &default=0;
	};
	
	global log_mime: event(rec: Info);
}

redef record connection += {
	mime:       Info &optional;
	mime_state: State &optional;
};

event bro_init()
	{
	Log::create_stream(MIME, [$columns=Info, $ev=log_mime]);
	}

function new_mime_session(c: connection): Info
	{
	local info: Info;
	
	info$ts=network_time();
	info$uid=c$uid;
	info$id=c$id;
	return info;
	}

function set_session(c: connection, new_entity: bool)
	{
	if ( ! c?$mime_state )
		c$mime_state = [];
	
	if ( ! c?$mime || new_entity )
		c$mime = new_mime_session(c);
	}

event mime_begin_entity(c: connection) &priority=10
	{
	set_session(c, T);

	++c$mime_state$level;
	
	if ( |c$service| > 0 )
		c$mime$app_protocol = join_string_set(c$service, ",");
	}

# This has priority -10 because other handlers need to know the current 
# content_len before it's updated by this handler.
event mime_segment_data(c: connection, length: count, data: string) &priority=-10
	{
	c$mime$content_len = c$mime$content_len + length;
	}
	
event mime_one_header(c: connection, h: mime_header_rec)
	{
	if ( h$name == "CONTENT-DISPOSITION" &&
	          /[fF][iI][lL][eE][nN][aA][mM][eE]/ in h$value )
		c$mime$filename = sub(h$value, /^.*[fF][iI][lL][eE][nN][aA][mM][eE]=\"?/, "");
	}
	
event mime_end_entity(c: connection) &priority=-5
	{
	# This check and the delete below are just to cope with a bug where 
	# mime_end_entity can be generated multiple times for the same event.
	if ( ! c?$mime )
		return;
		
	Log::write(MIME, c$mime);
	
	delete c$mime;
	}
