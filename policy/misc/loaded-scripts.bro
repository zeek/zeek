module LoadedScripts;

export {
	redef enum Log::ID += { LOADED_SCRIPTS };
	
	type Info: record {
		depth:  count  &log;
		name:   string &log;
	};
}

event bro_init()
	{
	Log::create_stream(LOADED_SCRIPTS, [$columns=Info]);
	}

event bro_script_loaded(path: string, level: count)
	{
	Log::write(LOADED_SCRIPTS, [$depth=level, $name=path]);
	}