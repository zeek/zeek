# @TEST-EXEC: zeek -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff local.log
# @TEST-EXEC: btest-diff remote.log
#
# The record value passed into the path_func should be allowed to contain a
# subset of the fields in the stream's columns.

@load base/utils/site
@load base/protocols/conn
@load base/frameworks/notice

redef Site::local_nets = {141.142.0.0/16};

function split_log(id: Log::ID, path: string, rec: record {id:conn_id;}): string
{
	return Site::is_local_addr(rec$id$orig_h) ? "local" : "remote";
}

event zeek_init()
{
	# Add a new filter to the Conn::LOG stream that logs only
	# timestamp and originator address.
	local filter: Log::Filter = [$name="dst-only", $path_func=split_log,
	                             $include=set("ts", "id.orig_h")];
	Log::add_filter(Conn::LOG, filter);
}
