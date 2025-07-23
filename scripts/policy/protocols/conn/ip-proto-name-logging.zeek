##! This script adds a string version of the ip_proto field. It's not recommended
##! to load this policy and the ip_proto removal policy at the same time, as
##! conn.log will end up with useless information in the log from this field.

@load base/protocols/conn

module Conn;

redef record Info += {
	## A string version of the ip_proto field
	ip_proto_name: string &log &optional;
};

event new_connection(c: connection) &priority=5 {
	if ( c$conn?$ip_proto && c$conn$ip_proto in IP::protocol_names )
		c$conn$ip_proto_name = IP::protocol_names[c$conn$ip_proto];
}
