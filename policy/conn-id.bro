# $Id: conn-id.bro 45 2004-06-09 14:29:49Z vern $

# Simple functions for generating ASCII connection identifiers.

@load port-name

function id_string(id: conn_id): string
	{
	return fmt("%s > %s",
		endpoint_id(id$orig_h, id$orig_p),
		endpoint_id(id$resp_h, id$resp_p));
	}

function reverse_id_string(id: conn_id): string
	{
	return fmt("%s < %s",
		endpoint_id(id$orig_h, id$orig_p),
		endpoint_id(id$resp_h, id$resp_p));
	}

function directed_id_string(id: conn_id, is_orig: bool): string
	{
	return is_orig ? id_string(id) : reverse_id_string(id);
	}
