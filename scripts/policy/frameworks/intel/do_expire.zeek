##! This script enables expiration for intelligence items.

@load base/frameworks/intel
@load policy/frameworks/intel/manage_groups

module Intel;

redef Intel::item_expiration = 10min;

hook item_expired(indicator: string, indicator_type: Type,
	metas: set[MetaData]) &priority=-10
	{
	for ( m in metas )
		{
		local item = Item($indicator=indicator, $indicator_type=indicator_type, $meta=m);
		disable_event_group_helper(item);
		}
	# Trigger removal of the expired item.
	break;
	}
