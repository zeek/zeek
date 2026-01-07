## Read a denylist.jsonl file in JSON Lines format
module Denylist;

type JsonLine: record {
   s: string;
};

type Entry: record {
	ip: addr;
	timestamp: time;
	reason: string;
};

global staged_denies: table[addr] of Entry;
global active_denies: table[addr] of Entry;

event Input::end_of_data(name: string, source: string)
	{
	if ( name != "denylist" )
		return;

	# Switch active and staging tables when input file has been read.
	active_denies = staged_denies;
	staged_denies = table();

	print network_time(), "end_of_data() active:", table_keys(active_denies);
	}


event Denylist::json_line(description: Input::EventDescription, tpe: Input::Event, l: string)
	{
	local parse_result = from_json(l, Entry);

	# Parsing of JSON may fail, so ignore anything invalid.
	if ( ! parse_result$valid )
		return;

	# Cast parsed value as Entry...
	local entry = parse_result$v as Entry;

	# ...and populate staging table.
	staged_denies[entry$ip] = entry;
	}

event zeek_init()
	{
	Input::add_event([
		$source="denylist.jsonl",
		$name="denylist",
		$reader=Input::READER_RAW,
		$mode=Input::REREAD,
		$fields=JsonLine,
		$ev=Denylist::json_line,
		$want_record=F,
	]);
	}
