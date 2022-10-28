# @TEST-DOC: Test zeekygen declaring script function for enum names;
#
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN; zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/conn
@load base/protocols/ftp
@load base/protocols/http

# Avoid the noise from reporter, broker, ...
global only: set[Log::ID] = [Log::UNKNOWN, HTTP::LOG, FTP::LOG, Conn::LOG];

event zeek_init()
	{
	local log_id_script = get_identifier_declaring_script("Log::ID");
	print "Log::ID", log_id_script;
	for ( name in enum_names("Log::ID") )
		{
		if ( lookup_ID(name) !in only )
			next;

		local enum_script = get_identifier_declaring_script(name);
		print name, log_id_script != enum_script ? "redef" : "original", enum_script;
		}
	}
