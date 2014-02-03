
@load base/utils/dir
@load base/utils/paths

module Unified2;

export {
	redef enum Log::ID += { LOG };

	## File to watch for Unified2 files.
	const watch_file = "" &redef;

	## Directory to watch for Unified2 records.
	const watch_dir = "" &redef;

	## The sid-msg.map file you would like to use for your alerts.
	const sid_msg = "" &redef;

	## The gen-msg.map file you would like to use for your alerts.
	const gen_msg = "" &redef;

	## The classification.config file you would like to use for your alerts.
	const classification_config = "" &redef;

	## Reconstructed "alert" which combines related events
	## and packets.
	global alert: event(f: fa_file, ev: Unified2::IDSEvent, pkt: Unified2::Packet);

	type PacketID: record {
		src_ip: addr;
		src_p: port;
		dst_ip: addr;
		dst_p: port;
	} &log;

	type Info: record {
		## Timestamp attached to the alert.
		ts:                 time     &log;
		## Addresses and ports for the connection.
		id:                 PacketID &log;
		## Sensor that originated this event.
		sensor_id:          count    &log;
		## Sig id for this generator.
		signature_id:       count    &log;
		## A string representation of the *signature_id* field if a sid_msg.map file was loaded.
		signature:          string   &log &optional;
		## Which generator generated the alert?
		generator_id:       count    &log;
		## A string representation of the *generator_id* field if a gen_msg.map file was loaded.
		generator:          string   &log &optional;
		## Sig revision for this id.
		signature_revision: count    &log;
		## Event classification.
		classification_id:  count    &log;
		## Descriptive classification string.
		classification:     string   &log &optional;
		## Event priority.
		priority_id:        count    &log;
		## Event ID.
		event_id:           count    &log;
		## Some of the packet data.
		packet:             string   &log &optional;
	} &log;

	## The event for accessing logged records.
	global log_unified2: event(rec: Info);
}

# Mappings for extended information from alerts.
global classification_map: table[count] of string;
global sid_map: table[count] of string;
global gen_map: table[count] of string;

# For reading in config files.
type OneLine: record {
	line: string;
};

function create_info(ev: IDSEvent): Info
	{
	local info = Info($ts=ev$ts,
	                  $id=PacketID($src_ip=ev$src_ip, $src_p=ev$src_p,
	                               $dst_ip=ev$dst_ip, $dst_p=ev$dst_p),
	                  $sensor_id=ev$sensor_id,
	                  $signature_id=ev$signature_id,
	                  $generator_id=ev$generator_id,
	                  $signature_revision=ev$signature_revision,
	                  $classification_id=ev$classification_id,
	                  $priority_id=ev$priority_id,
	                  $event_id=ev$event_id);

	if ( ev$signature_id in sid_map )
		info$signature=sid_map[ev$signature_id];
	if ( ev$generator_id in gen_map )
		info$generator=gen_map[ev$generator_id];
	if ( ev$classification_id in classification_map )
		info$classification=classification_map[ev$classification_id];

	return info;
	}

redef record fa_file += {
	## Recently received IDS events.  This is primarily used
	## for tying together Unified2 events and packets.
	u2_events: table[count] of Unified2::IDSEvent
		&optional &create_expire=5sec
		&expire_func=function(t: table[count] of Unified2::IDSEvent, event_id: count): interval
			{
			Log::write(LOG, create_info(t[event_id]));
			return 0secs;
			};
};

event Unified2::read_sid_msg_line(desc: Input::EventDescription, tpe: Input::Event, line: string)
	{
	local parts = split_n(line, / \|\| /, F, 100);
	if ( |parts| >= 2 && /^[0-9]+$/ in parts[1] )
		sid_map[to_count(parts[1])] = parts[2];
	}

event Unified2::read_gen_msg_line(desc: Input::EventDescription, tpe: Input::Event, line: string)
	{
	local parts = split_n(line, / \|\| /, F, 3);
	if ( |parts| >= 2 && /^[0-9]+$/ in parts[1] )
		gen_map[to_count(parts[1])] = parts[3];
	}

event Unified2::read_classification_line(desc: Input::EventDescription, tpe: Input::Event, line: string)
	{
	local parts = split_n(line, /: /, F, 2);
	if ( |parts| == 2 )
		{
		local parts2 = split_n(parts[2], /,/, F, 4);
		if ( |parts2| > 1 )
			classification_map[|classification_map|+1] = parts2[1];
		}
	}

event bro_init() &priority=5
	{
	Log::create_stream(Unified2::LOG, [$columns=Info, $ev=log_unified2]);

	if ( sid_msg != "" )
		{
		Input::add_event([$source=sid_msg,
		                  $reader=Input::READER_RAW,
		                  $mode=Input::REREAD,
		                  $name=sid_msg,
		                  $fields=Unified2::OneLine,
		                  $want_record=F,
		                  $ev=Unified2::read_sid_msg_line]);
		}

	if ( gen_msg != "" )
		{
		Input::add_event([$source=gen_msg,
		                  $name=gen_msg,
		                  $reader=Input::READER_RAW,
		                  $mode=Input::REREAD,
		                  $fields=Unified2::OneLine,
		                  $want_record=F,
		                  $ev=Unified2::read_gen_msg_line]);
		}

	if ( classification_config != "" )
		{
		Input::add_event([$source=classification_config,
		                  $name=classification_config,
		                  $reader=Input::READER_RAW,
		                  $mode=Input::REREAD,
		                  $fields=Unified2::OneLine,
		                  $want_record=F,
		                  $ev=Unified2::read_classification_line]);
		}

	if ( watch_dir != "" )
		{
		Dir::monitor(watch_dir, function(fname: string)
			{
			Input::add_analysis([$source=fname,
			                     $reader=Input::READER_BINARY,
			                     $mode=Input::STREAM,
			                     $name=fname]);
			}, 10secs);
		}

	if ( watch_file != "" )
		{
		Input::add_analysis([$source=watch_file,
		                     $reader=Input::READER_BINARY,
		                     $mode=Input::STREAM,
		                     $name=watch_file]);
		}
	}

event file_new(f: fa_file)
	{
	local file_dir = "";
	local parts = split_all(f$source, /\/[^\/]*$/);
	if ( |parts| == 3 )
		file_dir = parts[1];

	if ( (watch_file != "" && f$source == watch_file) || 
	     (watch_dir != "" && compress_path(watch_dir) == file_dir) )
		{
		Files::add_analyzer(f, Files::ANALYZER_UNIFIED2);
		f$u2_events = table();
		}
	}

event unified2_event(f: fa_file, ev: Unified2::IDSEvent)
	{
	f$u2_events[ev$event_id] = ev;
	}

event unified2_packet(f: fa_file, pkt: Unified2::Packet)
	{
	if ( f?$u2_events && pkt$event_id in f$u2_events)
		{
		local ev = f$u2_events[pkt$event_id];
		event Unified2::alert(f, ev, pkt);
		delete f$u2_events[pkt$event_id];
		}
	}

event Unified2::alert(f: fa_file, ev: IDSEvent, pkt: Packet)
	{
	local info = create_info(ev);
	info$packet=pkt$data;
	Log::write(LOG, info);
	}

event file_state_remove(f: fa_file)
	{
	if ( f?$u2_events )
		{
		# In case any events never had matching packets, flush
		# the extras to the log.
		for ( i in f$u2_events )
			{
			Log::write(LOG, create_info(f$u2_events[i]));
			}
		}
	}
