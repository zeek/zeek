@load base/frameworks/intel

module Intel;

export {
	global enable_event_group_helper: function(item: Item);
	global disable_event_group_helper: function(item: Item);
}

global intel_type_file_map: table[Type] of set[string];

event zeek_init()
	{
	intel_type_file_map = table();

	local types = enum_names(Type);

	for ( t in types )
		{
		if ( has_event_group(t) )
			disable_event_group(t);
		}
	}

function enable_event_group_helper(item: Item)
	{
	local t = item$indicator_type;
	local t_str = fmt("%s", t);

	if ( ! has_event_group(t_str) )
		return;

	if ( t !in intel_type_file_map )
		intel_type_file_map[t] = set();

	local f = item$meta$source;

	if ( f in intel_type_file_map[t] )
		return;

	add intel_type_file_map[t][f];
	enable_event_group(t_str);
	}

function disable_event_group_helper(item: Item)
	{
	local t = item$indicator_type;
	local t_str = fmt("%s", t);

	if ( ! has_event_group(t_str) )
		return;

	local f = item$meta$source;

	if ( f !in intel_type_file_map[t] )
		return;

	delete intel_type_file_map[t][f];
	if ( |intel_type_file_map[t]| > 0 )
		return;

	delete intel_type_file_map[t];
	disable_event_group(t_str);
	}

event Intel::read_entry(desc: Input::EventDescription, tpe: Input::Event, item: Item) &priority=10
	{
	enable_event_group_helper(item);
	}

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
event Intel::insert_item(item: Item) &priority=10
	{
	enable_event_group_helper(item);
	}

event Intel::remove_item(item: Item, purge_indicator: bool) &priority=10
	{
	disable_event_group_helper(item);
	}
@endif

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::WORKER )
event Intel::insert_indicator(item: Item) &priority=10
	{
	enable_event_group_helper(item);
	}

event remove_indicator(item: Item) &priority=10
	{
	disable_event_group_helper(item);
	}
@endif