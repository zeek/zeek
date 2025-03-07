##! This script adds information about matched DPD signatures to the connection
##! log.

@load base/protocols/conn

module Conn;

export {
	## Enable logging of speculative services in conn.log's service field.
	## The speculative service is added prefixed by "~" in case a DPD signature
	## matched while the DPD buffer was exhausted and the service has not
	## already been properly confirmed.
	option track_speculative_services_in_connection = F;
}

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

event connection_state_remove(c: connection) &priority=10
	{
	if ( |c$speculative_service| == 0 )
		return;

	local sp_service = "";
	for ( s in c$speculative_service )
		{
		sp_service = sp_service == "" ? s : cat(sp_service, ",", s);

		if ( track_speculative_services_in_connection && s !in c$service )
			add c$service[cat("~", s)];
		}

	if ( sp_service != "" )
		{
		set_conn(c, F);
		c$conn$speculative_service = to_lower(sp_service);
		}
	}

event protocol_late_match(c: connection, atype: Analyzer::Tag)
	{
	local analyzer = Analyzer::name(atype);
	add c$speculative_service[analyzer];
	}
