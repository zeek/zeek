module LoadedScripts;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		depth:  count  &log;
		name:   string &log;
	};
}

event bro_init()
	{
	Log::create_stream(LoadedScripts::LOG, [$columns=Info]);
	}

event bro_script_loaded(path: string, level: count)
	{
	Log::write(LoadedScripts::LOG, [$depth=level, $name=path]);
	}