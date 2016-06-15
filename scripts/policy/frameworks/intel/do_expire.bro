
@load base/frameworks/intel

module Intel;

hook item_expired(indicator: string, indicator_type: Type,
	metas: set[MetaData]) &priority=-10
	{
	break;
	}
