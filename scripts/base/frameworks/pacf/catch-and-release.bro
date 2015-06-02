##! Implementation of catch-and-release functionality for Pacf

module Pacf;

export {
	## Stops all packets involving an IP address from being forwarded. This function
	## uses catch-and-release functionality, where the IP address is only dropped for
	## a short amount of time that is incremented steadily when the IP is encountered
	## again.
	##
	## a: The address to be dropped.
	##
	## t: How long to drop it, with 0 being indefinitly.
	##
	## location: An optional string describing where the drop was triggered.
	##
	## Returns: The id of the inserted rule on succes and zero on failure.
	global drop_address_catch_release: function(a: addr, location: string &default="") : string;

	const catch_release_intervals: vector of interval = vector(10min, 1hr, 24hrs, 7days) &redef;
}

function per_block_interval(t: table[addr] of count, idx: addr): interval
	{
	local ct = t[idx];

	# watch for the time of the next block...
	local blocktime = catch_release_intervals[ct];
	if ( (ct+1) in catch_release_intervals )
		blocktime = catch_release_intervals[ct+1];

	return blocktime;
	}

# This is the internally maintained table containing all the currently going on catch-and-release
# blocks.
global blocks: table[addr] of count = {}
	&create_expire=0secs
	&expire_func=per_block_interval;

function current_block_interval(s: set[addr], idx: addr): interval
	{
	if ( idx !in blocks )
		{
		Reporter::error(fmt("Address %s not in blocks while inserting into current_blocks!", idx));
		return 0sec;
		}

	return catch_release_intervals[blocks[idx]];
	}

global current_blocks: set[addr] = set()
	&create_expire=0secs
	&expire_func=current_block_interval;

function drop_address_catch_release(a: addr, location: string &default=""): string
	{
	if ( a in blocks )
		{
		Reporter::warning(fmt("Address %s already blocked using catch-and-release - ignoring duplicate", a));
		return "";
		}

	local block_interval = catch_release_intervals[0];
	local ret = drop_address(a, block_interval, location);
	if ( ret != "" )
		{
		blocks[a] = 0;
		add current_blocks[a];
		}

	return ret;
	}

function check_conn(a: addr)
	{
	if ( a in blocks )
		{
		if ( a in current_blocks )
			# block has not been applied yet?
			return;

		# ok, this one returned again while still in the backoff period.
		local try = blocks[a];
		if ( (try+1) in catch_release_intervals )
			++try;

		blocks[a] = try;
		add current_blocks[a];
		local block_interval = catch_release_intervals[try];
		drop_address(a, block_interval, "Re-drop by catch-and-release");
		}
	}

event new_connection(c: connection)
	{
	# let's only check originating connections...
	check_conn(c$id$orig_h);
	}
