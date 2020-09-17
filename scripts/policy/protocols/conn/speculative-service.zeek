##! This script adds information about matched DPD signatures to the connection
##! log.

@load base/protocols/conn

module Conn;

redef record Info += {
	## Protocol that was determined by a matching signature after the beginning
	## of a connection. In this situation no analyzer can be attached and hence
	## the data cannot be analyzed nor the protocol can be confirmed.
	speculative_service: string &log &optional;
};

redef record connection += {
	speculative_service: set[string] &default=string_set();
};

redef dpd_match_only_beginning = F;
redef dpd_late_match_stop = T;

hook finalize_speculative_service(c: connection)
	{
	local sp_service = "";
	for ( s in c$speculative_service )
		sp_service = sp_service == "" ? s : cat(sp_service, ",", s);

	if ( sp_service != "" )
		c$conn$speculative_service = to_lower(sp_service);
	}

event protocol_late_match(c: connection, atype: Analyzer::Tag)
	{
	local analyzer = Analyzer::name(atype);
	add c$speculative_service[analyzer];
	Conn::register_removal_hook(c, finalize_speculative_service);
	}
