##! Log the loaded scripts.
@load base/utils/paths

module LoadedScripts;

export {
	redef enum Log::ID += { LOG };
	
	type Info: record {
		## Name of the script loaded potentially with spaces included
		## before the file name to indicate load depth.  The convention
		## is two spaces per level of depth.
		name: string &log;
	};
}

const depth: table[count] of string = {
	[0]  = "",
	[1]  = "  ",
	[2]  = "    ",
	[3]  = "      ",
	[4]  = "        ",
	[5]  = "          ",
	[6]  = "            ",
	[7]  = "              ",
	[8]  = "                ",
	[9]  = "                  ",
	[10] = "                    ",
};

event bro_init() &priority=5
	{
	Log::create_stream(LoadedScripts::LOG, [$columns=Info]);
	}

event bro_script_loaded(path: string, level: count)
	{
	Log::write(LoadedScripts::LOG, [$name=cat(depth[level], compress_path(path))]);
	}
