##! A few predefined notice_action_filters.

@load notice/base

module Notice;

export {
	const ignore_tallies_at_shutdown = T &redef;
	const notice_once_per_orig_tally_interval = 1hr &redef;
	
	global tallies: table[string] of count &default = 0;
	
	## Reports a specific NoticeType the first time we see it for a source.  
	## From then on, tally instances per source.
	#global notice_once_per_orig: table[Info, addr] of count
	#	&default=0 &read_expire=5hrs;
	
	global ignore_action: function(n: Notice::Info, a: Notice::Action): Notice::Action;
	global file_action: function(n: Notice::Info, a: Notice::Action): Notice::Action;
	global send_email_action: function(n: Notice::Info, a: Notice::Action): Notice::Action;
	global send_page_action: function(n: Notice::Info, a: Notice::Action): Notice::Action;
	global tally_notice_type: function(n: Notice::Info, a: Notice::Action): Notice::Action;
	global tally_notice_type_and_ignore: function(n: Notice::Info, a: Notice::Action): Notice::Action;
	global file_local_bro_notices: function(n: Notice::Info, a: Notice::Action): Notice::Action;
	global file_if_remote: function(n: Notice::Info, a: Notice::Action): Notice::Action;
}


function ignore_action(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return ACTION_IGNORE;
	}

function file_action(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return ACTION_FILE;
	}

function send_email_action(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return ACTION_EMAIL;
	}

function send_page_action(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return ACTION_PAGE;
	}


function tally_notice(s: string)
	{
	++tallies[s];
	}

function tally_notice_type(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	tally_notice(fmt("%s", n$note));
	return ACTION_FILE;
	}

function tally_notice_type_and_ignore(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	tally_notice(fmt("%s", n$note));
	return ACTION_IGNORE;
	}

function file_local_bro_notices(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	if ( n$src_peer$is_local )
		return ACTION_FILE;

	return a;
	}

function file_if_remote(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	if ( n?$src && ! is_local_addr(n$src) )
		return ACTION_FILE;

	return a;
	}

#event notice_alarm_per_orig_tally(n: Notice::Info, host: addr)
#	{
#	local i = notice_once_per_orig[n$note, host];
#	if ( i > 1 )
#		{
#		local msg = fmt("%s seen %d time%s from %s",
#				n$note, i, i > 1 ? "s" : "", host);
#		NOTICE([$note=Notice_Tally, $msg=msg, $src=host, $n=i]);
#		}
#	}
#
#function notice_alarm_per_orig(n: Notice::Info, a: Notice::Action): Notice::Action
#	{
#	local host = n$src;
#	
#	++notice_once_per_orig[n$note, host];
#	
#	if ( notice_once_per_orig[n$note, host] > 1 )
#		return ACTION_FILE;
#	
#	schedule notice_once_per_orig_tally_interval
#		{ notice_alarm_per_orig_tally(n, host) };
#	
#	return ACTION_ALARM_ALWAYS;
#	}

event bro_done()
	{
	if ( ignore_tallies_at_shutdown )
		return;
		
	for ( s in tallies )
		{
		local n = tallies[s];
		local msg = fmt("%s (%d time%s)", s, n, n > 1 ? "s" : "");
		NOTICE([$note=Notice_Tally, $msg=msg, $n=n]);
		}
	}
