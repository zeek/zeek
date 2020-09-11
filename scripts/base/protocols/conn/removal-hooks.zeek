##! Adds a framework for registering "connection removal hooks".
##! All registered hooks for a given connection get run within the
##! :zeek:see:`connection_state_remove` event for that connection.
##! This functionality is useful from a performance/scaling concern:
##! if every new protocol-analysis script uses
##! :zeek:see:`connection_state_remove` to implement its finalization/cleanup
##! logic, then all connections take the performance hit of dispatching that
##! event, even if they aren't related to that specific protocol.

module Conn;

export {
	## A hook function for use with either :zeek:see:`Conn::register_removal_hook`
	## or :zeek:see:`Conn::unregister_removal_hook`.  The :zeek:see:`connection`
	## argument refers to the connection currently being removed within a
	## :zeek:see:`connection_state_remove` event.
	type RemovalHook: hook(c: connection);

	## Register a hook that will later be called during a connection's
	## :zeek:see:`connection_state_remove` event.
	##
	## c: The associated connection whose :zeek:see:`connection_state_remove`
	##    event should trigger a callback to *hk*.
	##
	## hk: The hook function to use as a callback.
	##
	## Returns: false if the provided hook was previously registered, else true.
	global register_removal_hook: function(c: connection, hk: RemovalHook): bool;

	## Unregister a hook that would have been called during a connection's
	## :zeek:see:`connection_state_remove` event such that it will no longer
	## be called.
	##
	## c: The associated connection whose :zeek:see:`connection_state_remove`
	##    event could have triggered a callback to *hk*.
	##
	## hk: The hook function that would have been used as a callback.
	##
	## Returns: true if the provided hook was previously registered, else false.
	global unregister_removal_hook: function(c: connection, hk: RemovalHook): bool;
}

redef record connection += {
	removal_hooks: set[RemovalHook] &optional;
};

function register_removal_hook(c: connection, hk: RemovalHook): bool
	{
	if ( c?$removal_hooks )
		{
		if ( hk in c$removal_hooks )
			return F;

		add c$removal_hooks[hk];
		return T;
		}

	c$removal_hooks = set(hk);
	return T;
	}

function unregister_removal_hook(c: connection, hk: RemovalHook): bool
	{
	if ( ! c?$removal_hooks )
		return F;

	if ( hk !in c$removal_hooks )
		return F;

	delete c$removal_hooks[hk];
	return T;
	}

event connection_state_remove(c: connection) &priority=-3
	{
	if ( c?$removal_hooks )
		for ( removal_hook in c$removal_hooks )
			hook removal_hook(c);
	}
