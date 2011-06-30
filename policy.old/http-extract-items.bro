# $Id:$

# Extracts the items from HTTP traffic, one per file.
# Files are named:
#
#    <prefix>.<n>.<orig-addr>_<orig-port>.<resp-addr>_<resp-port>.<is-orig>
#
# where <prefix> is a redef'able prefix (default: "http-item"), <n> is
# a number uniquely identifying the item, the next four are describe
# the connection tuple, and <is-orig> is "orig" if the item was transferred
# from the originator to the responder, "resp" otherwise.

@load http-reply

module HTTP_extract_items;

global prefix = "http-item" &redef;
global item_file: table[conn_id] of file;
global nitems = 0;

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	local id = c$id;
	if ( id !in item_file )
		{
		# Create a new file for this one.
		local fname = fmt("%s.%d.%s_%d.%s_%d.%s",
					prefix, ++nitems,
					id$orig_h, id$orig_p,
					id$resp_h, id$resp_p,
					is_orig ? "orig" : "resp");
		item_file[id] = open(fname);
		}

	write_file(item_file[id], data);
	}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	delete item_file[c$id];
	}
