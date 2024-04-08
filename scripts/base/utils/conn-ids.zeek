##! Simple functions for generating ASCII strings from connection IDs.

module GLOBAL;

export {
	## Takes a conn_id record and returns a string representation with the
	## general data flow appearing to be from the connection originator
	## on the left to the responder on the right.
	global id_string: function(id: conn_id): string;

	## Takes a conn_id record and returns a string representation with the
	## general data flow appearing to be from the connection responder
	## on the right to the originator on the left.
	global reverse_id_string: function(id: conn_id): string;

	## Calls :zeek:id:`id_string` or :zeek:id:`reverse_id_string` if the
	## second argument is T or F, respectively.
	global directed_id_string: function(id: conn_id, is_orig: bool): string;
}

### Note, this function is known to -O ZAM (see `known_funcs` and
### `ScriptOptBuiltinExpr::FUNC_ID_STRING` in src/script_opt/Expr.cc),
### which replaces it with a custom instruction, so if changed here,
### that needs to be changed too.
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
