
@load protocols/ssh/detect-bruteforcing

redef SSH::password_guesses_limit=10;

event NetControl::init()
	{
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == SSH::Password_Guessing )
		NetControl::drop_address(n$src, 60min);
	}
