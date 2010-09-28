# $Id$

# The cluster manager will inform us with these events if he's interested in
# further connection attempts from that source.

global watch_addr_table: set[addr] &read_expire=7days &persistent;

global address_seen_again: event(a: addr);

event address_restored(a: addr)
	{
	add watch_addr_table[a];
	}

event address_dropped(a: addr)
	{
	delete watch_addr_table[a];
	}

event address_cleared(a: addr)
	{
	delete watch_addr_table[a];
	}

# We need to forward the new connection attempt.
event new_connection(c: connection)
	{
	local a = c$id$orig_h;
	if ( a in watch_addr_table )
		{
		event Drop::address_seen_again(a);
		delete watch_addr_table[a];
		}
	}


