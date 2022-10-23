##! Log the loaded scripts.
@load base/utils/paths

module LoadedScripts;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	type Info: record {
		## Name of the script loaded potentially with spaces included
		## before the file name to indicate load depth.  The convention
		## is two spaces per level of depth.
		name: string &log;
	};
}

# This is inefficient; however, since this script only executes once on
# startup, this should be ok.
function get_indent(level: count): string
	{
	local out = "";
	while ( level > 0 )
		{
		--level;
		out = out + "  ";
		}
	return out;
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LoadedScripts::LOG, [$columns=Info, $path="loaded_scripts", $policy=log_policy]);
	}

event zeek_script_loaded(path: string, level: count)
	{
	Log::write(LoadedScripts::LOG, [$name=cat(get_indent(level), compress_path(path))]);
	}
