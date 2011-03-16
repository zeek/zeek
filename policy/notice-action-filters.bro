# A few predefined notice_action_filters (see notice.bro).

@load site
@load notice

function ignore_notice(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return NOTICE_IGNORE;
	}

function file_notice(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return NOTICE_FILE;
	}

function send_email_notice(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return NOTICE_EMAIL;
	}

function send_page_notice(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return NOTICE_PAGE;
	}

global notice_tallies: table[string] of count &default = 0;

function tally_notice(s: string)
	{
	++notice_tallies[s];
	}

function tally_notice_type(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	tally_notice(fmt("%s", n$note));
	return NOTICE_FILE;
	}

function tally_notice_type_and_ignore(n: Notice::Info, a: Notice::Action)
		: Notice::Action
	{
	tally_notice(fmt("%s", n$note));
	return NOTICE_IGNORE;
	}

function file_local_bro_notices(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	#if ( n$src_peer$is_local )
	#	return NOTICE_FILE;

	return a;
	}

function file_if_remote(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	if ( n?$src && ! is_local_addr(n$src) )
		return NOTICE_FILE;

	return a;
	}

function drop_source(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	return NOTICE_DROP;
	}


event bro_done()
	{
	for ( s in notice_tallies )
		{
		local n = notice_tallies[s];
		local msg = fmt("%s (%d time%s)", s, n, n > 1 ? "s" : "");
		NOTICE([$note=NoticeTally, $msg=msg, $n=n]);
		}
	}

# notice_alarm_per_orig.
#
# Reports a specific NoticeType the first time we see it for a source.  From
# then on, we tally instances per source.

#global notice_once_per_orig: table[Notice::Info, addr] of count
#	&default=0 &read_expire=5hrs;
global notice_once_per_orig_tally_interval = 1 hr &redef;

event notice_alarm_per_orig_tally(n: Notice::Info, host: addr)
	{
	#local i = notice_once_per_orig[n$note, host];
	#if ( i > 1 )
	#	{
	#	local msg = fmt("%s seen %d time%s from %s",
	#			n$note, i, i > 1 ? "s" : "", host);
	#	NOTICE([$note=NoticeTally, $msg=msg, $src=host, $n=i]);
	#	}
	}

function notice_alarm_per_orig(n: Notice::Info, a: Notice::Action): Notice::Action
	{
	local host = n$src;

	#++notice_once_per_orig[n$note, host];

	#if ( notice_once_per_orig[n$note, host] > 1 )
	#	return NOTICE_FILE;
    #
	#schedule notice_once_per_orig_tally_interval
	#	{ notice_alarm_per_orig_tally(n, host) };

	return NOTICE_ALARM_ALWAYS;
	}
