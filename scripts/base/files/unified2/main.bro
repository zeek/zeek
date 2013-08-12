
@load base/utils/dir
@load base/utils/paths

module Unified2;

export {
	## Directory to watch for Unified2 files.
	const watch_file = "" &redef;

	## File to watch for Unified2 records.
	const watch_dir = "" &redef;

	## Reconstructed "alert" which combines related events
	## and packets.
	global alert: event(f: fa_file, ev: Unified2::IDSEvent, pkt: Unified2::Packet);

	type Info: record {
		## The last received IDS event.  This is primarily used 
		## for tying together Unified2 events and packets.
		current_event: Unified2::IDSEvent &optional;
	};

	redef record fa_file += {
		## Add a field to store per-file state about Unified2
		## files.
		unified2: Info &optional;
	};
}

event bro_init()
	{
	if ( watch_dir != "" )
		{
		Dir::monitor(watch_dir, function(fname: string)
			{
			Input::add_analysis([$source=fname, 
			                     $reader=Input::READER_BINARY,
			                     $mode=Input::MANUAL, 
			                     $name=fname]);
			}, 10secs);
		}

	if ( watch_file != "" )
		{
		Input::add_analysis([$source=watch_file, 
		                     $reader=Input::READER_BINARY,
		                     $mode=Input::MANUAL, 
		                     $name=watch_file]);
		}
	}

event file_new(f: fa_file)
	{
	local file_dir = "";
	local parts = split_all(f$source, /\/[^\/]*$/);
	if ( |parts| == 3 )
		file_dir = parts[1];

	if ( f$source in watch_file || 
		compress_path(watch_dir) == file_dir )
		{
		Files::add_analyzer(f, Files::ANALYZER_UNIFIED2);
		f$unified2 = Info();
		}
	}

event unified2_event(f: fa_file, ev: Unified2::IDSEvent)
	{
	f$unified2$current_event = ev;
	}

event unified2_packet(f: fa_file, pkt: Unified2::Packet)
	{
	if ( f$unified2?$current_event )
		{
		event Unified2::alert(f, f$unified2$current_event, pkt);
		delete f$unified2$current_event;
		}
	}
