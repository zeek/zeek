@load conn-id
@load ncp

module NCP_tag;

global log = open_log_file("ncp-tag") &redef;

const ncp_request_type = {
[ 0x11 ] = "print",
[ 0x16, 0x68 ] = "directory",
} &default = function(code: count): string
	{
	return fmt("unknown(%x)", code);
	};

event ncp_request(c: connection, frame_type: count, length: count, func: count)
	{
	print log, fmt("%.6f %s NCP request type=%s function=%s",
		network_time(), id_string(c$id),
		NCP::ncp_frame_type_name[frame_type],
		NCP::ncp_function_name[func]);
	}

event ncp_reply(c: connection, frame_type: count, length: count, completion_code: count)
	{
	}
