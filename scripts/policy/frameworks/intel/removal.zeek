##! This script enables removal of intelligence items.

@load base/frameworks/intel

module Intel;

export {
	redef record Intel::MetaData += {
		## A boolean value to indicate whether the item should be removed.
		remove: bool &default=F;
	};
}

hook Intel::filter_item(item: Item)
	{
	if ( item$meta$remove )
		{
		Intel::remove(item);
		# Prevent readding
		break;
		}
	}

