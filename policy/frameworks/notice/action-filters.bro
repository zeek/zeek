##! A few predefined notice_action_filters.
##!  This is completely and utterly not working right now!!!!!


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
	
	global ignore_it: function(nt: Notice::Type): Notice::PolicyItem;
	global file_it: function(nt: Notice::Type): Notice::PolicyItem;
	global send_email: function(nt: Notice::Type): Notice::PolicyItem;
	global send_page: function(nt: Notice::Type): Notice::PolicyItem;
	global tally_notice_type: function(nt: Notice::Type): Notice::PolicyItem;
	global tally_notice_type_and_ignore: function(nt: Notice::Type): Notice::PolicyItem;
	global file_local_bro_notices: function(nt: Notice::Type): Notice::PolicyItem;
	global file_if_remote: function(nt: Notice::Type): Notice::PolicyItem;
}

function action2policy_item(nt: Notice::Type, action: Notice::Action): Notice::PolicyItem
	{
	return [$result=action,
	        $pred(n: Notice::Info) = { return n$note == nt; },
	        $priority=5];
	}

function ignore_it(nt: Notice::Type): Notice::PolicyItem
	{
	return action2policy_item(nt, ACTION_IGNORE);
	}

function file_it(nt: Notice::Type): Notice::PolicyItem
	{
	return action2policy_item(nt, ACTION_FILE);
	}

function send_email(nt: Notice::Type): Notice::PolicyItem
	{
	return action2policy_item(nt, ACTION_EMAIL);
	}

function send_page_action(nt: Notice::Type): Notice::PolicyItem
	{
	return action2policy_item(nt, ACTION_PAGE);
	}


#function tally_notice(s: string)
#	{
#	++tallies[s];
#	}
#
#function tally_notice_type(nt: Notice::Type): Notice::PolicyItem
#	{
#	tally_notice(fmt("%s", n$note));
#	return action2policy_item(nt, ACTION_FILE);
#	}
#
#function tally_notice_type_and_ignore(nt: Notice::Type): Notice::PolicyItem
#	{
#	tally_notice(fmt("%s", n$note));
#	return action2policy_item(nt, ACTION_IGNORE);
#	}
#
#function file_local_bro_notices(nt: Notice::Type): Notice::PolicyItem
#	{
#	if ( n$src_peer$is_local )
#		return action2policy_item(nt, ACTION_FILE);
#	else
#		return action2policy_item(nt, n$action);
#	}
#
#function file_if_remote(nt: Notice::Type): Notice::PolicyItem
#	{
#	if ( n?$src && ! is_local_addr(n$src) )
#		return action2policy_item(nt, ACTION_FILE);
#	else
#		return action2policy_item(nt, n$action);
#	}




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
