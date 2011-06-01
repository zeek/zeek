##! Simple functions for generating ASCII strings from connection IDs.

module GLOBAL;

export {
	## Takes a conn_id record and returns a string representation with the 
	## the general data flow appearing to be toward the right.
	global id_string: function(id: conn_id): string;
	
	## Takes a conn_id record and returns a string representation with the 
	## the general data flow appearing to be toward the left.
	global reverse_id_string: function(id: conn_id): string;
	
	## Calls either the :bro:id:`id_string` or :bro:id:`reverse_id_string`
	## function depending on the second argument.
	global directed_id_string: function(id: conn_id, is_orig: bool): string;
}

function id_string(id: conn_id): string
	{
	return fmt("%s:%d > %s:%d",
		id$orig_h, id$orig_p,
		id$resp_h, id$resp_p);
	}

function reverse_id_string(id: conn_id): string
	{
	return fmt("%s:%d < %s:%d",
		id$orig_h, id$orig_p,
		id$resp_h, id$resp_p);
	}

function directed_id_string(id: conn_id, is_orig: bool): string
	{
	return is_orig ? id_string(id) : reverse_id_string(id);
	}
