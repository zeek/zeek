# $Id: clear-passwords.bro 4758 2007-08-10 06:49:23Z vern $

# Monitoring for use of cleartext passwords.

@load ftp
@load login
@load pop3
@load irc

const passwd_file = open_log_file("passwords") &redef;

# ftp, login and pop3 call login_{success,failure}, which in turn
# calls account_tried(), so we can snarf all at once here:
event account_tried(c: connection, user: string, passwd: string)
	{
	print passwd_file, fmt("%s account name '%s', password '%s': %s",
				is_local_addr(c$id$orig_h) ? "local" : "remote",
				user, passwd, id_string(c$id));
	}

# IRC raises a different event on login, so we hook into it here:
event irc_join_message(c: connection, info_list: irc_join_list)
	{
	for ( l in info_list)
		{
		print passwd_file,  fmt("IRC JOIN name '%s', password '%s'",
					l$nick, l$password);
		}
	}

# Raised if IRC user tries to become operator:
event irc_oper_message(c: connection, user: string, password: string)
	{
	print passwd_file, fmt("IRC OPER name '%s', password '%s'",
				user, password);
	}
