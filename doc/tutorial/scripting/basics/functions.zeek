# Functions have similar definitions to events, but use the 'function'
# keyword. You may also specify a return type after the function parameters
# with a colon.
#
# Syntax: function name(arg1: type1, arg2: type2): return_type
function is_internal(cid: conn_id): bool
	{
	# Have a dummy local subnet
	local internal_net: subnet = 10.0.0.0/8;

	# These two if statements could be combined, for demonstration they
	# are separate.
	if ( cid$orig_h in internal_net )
		return T;

	if ( cid$resp_h in internal_net )
		return T;

	# Neither case matched, so return false.
	return F;
	}

event new_connection(c: connection)
	{
	# Pass c$id, not the connection, so that it is a conn_id
	if ( ! is_internal(c$id) )
		print fmt("Connection between %s and %s is not internal!",
			c$id$orig_h, c$id$resp_h);
	}
