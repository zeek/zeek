##! This script enables expiration for intelligence items.

@load base/frameworks/intel

module Intel;

redef Intel::item_expiration = 10min;

hook item_expired(indicator: string, indicator_type: Type,
	metas: set[MetaData]) &priority=-10
	{
	# Trigger removal of the expired item.
	break;
	}
