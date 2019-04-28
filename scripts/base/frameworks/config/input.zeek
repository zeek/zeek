##! File input for the configuration framework using the input framework.

@load ./main
@load base/frameworks/cluster

module Config;

export {
	## Configuration files that will be read off disk. Files are reread
	## every time they are updated so updates should be atomic with "mv"
	## instead of writing the file in place.
	##
	## If the same configuration option is defined in several files with
	## different values, behavior is unspecified.
	const config_files: set[string] = {} &redef;

	## Read specified configuration file and apply values; updates to file
	## are not tracked.
	global read_config: function(filename: string);
}

global current_config: table[string] of string = table();

type ConfigItem: record {
	option_nv: string;
};

type EventFields: record {
	option_name: string;
	option_val: string;
};

event config_line(description: Input::EventDescription, tpe: Input::Event, p: EventFields)
	{
	}

event zeek_init() &priority=5
	{
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		return;

	for ( fi in config_files )
		Input::add_table([$reader=Input::READER_CONFIG,
			$mode=Input::REREAD,
			$source=fi,
			$name=cat("config-", fi),
			$idx=ConfigItem,
			$val=ConfigItem,
			$want_record=F,
			$destination=current_config]);
	}

event InputConfig::new_value(name: string, source: string, id: string, value: any)
	{
	if ( sub_bytes(name, 1,  15) != "config-oneshot-" && source !in config_files )
		return;

	Config::set_value(id, value, source);
	}

function read_config(filename: string)
	{
	# Only read the configuration on the manager. The other nodes are being fed
	# from the manager.
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
		return;

	local iname = cat("config-oneshot-", filename);

	Input::add_event([$reader=Input::READER_CONFIG,
		$mode=Input::MANUAL,
		$source=filename,
		$name=iname,
		$fields=EventFields,
		$ev=config_line]);
	Input::remove(iname);
	}
