module Intel;

export {
	type Indexes: record {
		hosts:   set[addr]            &default=set();
		strings: set[string, SubType] &default=set();
	};

	redef record Plugin += {
		index: function(item: Item) &optional;
	}

	## Rebuild indexes this interval after any change to data if there 
	## have been no other changes.
	const rebuild_indexes_min = 1min &redef;
	## Wait no longer than this interval to update indexes after any
	## change to the data.
	const rebuild_indexes_max = 5min &redef;

	global indexing_done: event();
}

local indexes: Indexes = [];

global last_index_rebuild = network_time();
global last_datastore_mod = network_time();


event reindex() &priority=5
	{
	local tmp_indexes: Indexes;
	for ( plugin in plugins )
		{
		for ( m in metas$metas )
			{
			add tmp_indexes$hosts[m$source];
			add tmp_indexes$strings[m$intent];

			#for ( ip in index_plugins )
			#	{
			#	ip$index(index, m);
			#	}
			}
		}
		indexes = 
		event indexing_done();
	}

event rebuild_indexes(triggered_at: time)
	{
	if ( network_time() - triggered_at >= rebuild_indexes_max ||
	     network_time() - last_datastore_mod >= rebuild_indexes_min )
		{
		reindex();
		}
	}

event Intel::new_item(item:: Item) &priority=5
	{
	last_datastore_mod = network_time();
	schedule rebuild_indexes_min { rebuild_indexes(network_time()) };
	}

event Intel::updated_item(item:: Item) &priority=5
	{
	last_datastore_mod = network_time();
	schedule rebuild_indexes_min { rebuild_indexes(network_time()) };
	}