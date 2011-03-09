# $Id: mail-alarms.bro 6811 2009-07-06 20:41:10Z robin $
#
# Script to prettify alarms into a form suitable for mailing out.
# Output is written to mail.log which can be mailed out via post-processor.

@load site
@load notice

module MailAlarms;

export 	{
	# If non-empty, we include only the given Notices into mail.
	global include_only: set[Notice] &redef;

	# If one of these networks is involved, we mark the entry with a quote 
	# symbol (i.e., ">"). Many mailers flag such lines in some fashion.
	global flag_nets: set[subnet] &redef;

	# Skip the notice types for the mails.
	global ignore: set[Notice] &redef;

	global output = open_log_file( "mail" );
	}

function do_msg(n: notice_info, line1: string, line2: string, line3: string, host: addr, name: string, dest: string)
	{
	if ( host != 0.0.0.0 )
		name = fmt("%s = %s", host, name);
	
	line1 = cat(line1, name);
	
	if ( dest == "" ) 
		{
		# Append to mail.log.
		print output, line1;
		print output, line2;
		if ( line3 != "" )
			print output, line3;
		}
	
	else 
		{
		line1 = str_shell_escape(line1);
		line2 = str_shell_escape(line2);
		line3 = str_shell_escape(line3);
		
		# Mail out an individual alarm. 
		local mail_cmd =
			fmt("( echo \"%s\"; echo \"%s\"; echo \"%s\" ) | %s -s \"[Bro Alarm] %s: %s\" %s",
				line1, line2, line3, mail_script, n$note, str_shell_escape(n$msg), dest);
		
		system(mail_cmd);
		}
	}

function message(msg: string, flag: bool, host: addr, n: notice_info, dest: string)
	{
	if ( length(include_only) > 0 && n$note !in include_only )
		return;
	
	local location = "";

	if ( host != 0.0.0.0 )
		location =  is_local_addr(host) ? "(L)" : "(R)";
	
	local line1 = fmt(">%s %D %s %s ", (flag ? ">" : " "), network_time(), n$note, location);
	local line2 = fmt("   %s", msg);   
	local line3 = "";

	if ( n?$captured )
		line3 = fmt("   [TM: %s]", n$captured);

	if ( host == 0.0.0.0 )
		{
		do_msg(n, line1, line2, line3, 0.0.0.0, "", dest);
		return;
		}
	
	when ( local name = lookup_addr(host) )
		{
		do_msg(n, line1, line2, line3, host, name, dest);
		}
	timeout 5secs
		{
		do_msg(n, line1, line2, line3, host, "(dns timeout)", dest);
		}
	}

function make_alarm(n: notice_info, dest: string)
	{
	if ( n$note in ignore )
		return;
	
	local pdescr = "local";
	
	if ( n?$src_peer )
		pdescr = n$src_peer?$descr ? n$src_peer$descr : fmt("%s", n$src_peer$host);

	local msg = fmt( "<%s> %s%s", pdescr, n$msg, n?$sub ? cat( " ", n$sub ) : "" );

	local orig = 0.0.0.0;
	local resp = 0.0.0.0;
	local host = 0.0.0.0;

	if ( n?$src )
		orig = host = n$src;

	if ( n?$conn )
		{
		orig = n$conn$id$orig_h;
		resp = n$conn$id$resp_h;
		}

	else if ( n?$id )
		{
		orig = n$id$orig_h;
		resp = n$id$resp_h;
		}

	if ( host == 0.0.0.0 )
		host = orig; 

	local flag = F;
	if ( orig in flag_nets || resp in flag_nets )
		flag = T;

	message(msg, flag, host, n, dest);
	}


event bro_init()
    {
    set_buf( output, F );
    }

event notice_alarm(n: notice_info, action: NoticeAction) &priority = -10
	{
	if ( is_remote_event() )
		return;

	make_alarm(n, "");
	}

function broctl_email_notice_to(n: notice_info, dest: string)
	{
	if ( reading_traces() || dest == "" )
		return;

	if ( dest == "" )
		return;
	
	make_alarm(n, dest);
	}

# Make the alarm mails nicer. 
redef email_notice_to = broctl_email_notice_to;
