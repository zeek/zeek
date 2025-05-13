@load base/frameworks/intel

module Intel;

export {
	global enable_event_group_helper: function(item: Item);
	global disable_event_group_helper: function(item: Item);
}

global intel_type_file_map: table[Type] of count;

event zeek_init()
	{
	intel_type_file_map = table() &default=0;

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
		intel_type_file_map[t] = 0;

	intel_type_file_map[t] += 1;
	enable_event_group(t_str);
	}

function disable_event_group_helper(item: Item)
	{
	local t = item$indicator_type;
	local t_str = fmt("%s", t);

	if ( ! has_event_group(t_str) )
		return;

	intel_type_file_map[t] -= 1;
	if ( |intel_type_file_map[t]| > 0 )
		return;

	delete intel_type_file_map[t];
	disable_event_group(t_str);
	}

hook Intel::insert_item(item: Item) &priority=-10
	{
	enable_event_group_helper(item);
	}

hook Intel::purge_item(item: Item) &priority=-10
	{
	disable_event_group_helper(item);
	}
