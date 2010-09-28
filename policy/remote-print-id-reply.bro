# $Id:$
#
# Load this script to support remote printing of variables.  The remote
# peer accesses these by loading remote-print-id.bro.

module PrintID;

global request_id_response: event(id: string, content: string);

event request_id(id: string)
	{
	if ( ! is_remote_event() )
		return;

	local val = lookup_ID(id);
	event request_id_response(id, fmt("%s", val));
	}
