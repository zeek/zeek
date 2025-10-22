module Conn;

export {
	## The record type which contains column fields of the connection log.
	type Info: record {
		ts:           time            &log;
		uid:          string          &log;
		id:           conn_id         &log;
		proto:        transport_proto &log;
		service:      string          &log &optional;
		duration:     interval        &log &optional;
		orig_bytes:   count           &log &optional;
		resp_bytes:   count           &log &optional;
		conn_state:   string          &log &optional;
		local_orig:   bool            &log &optional;
		local_resp:   bool            &log &optional;
		missed_bytes: count           &log &default=0;
		history:      string          &log &optional;
		orig_pkts:     count      &log &optional;
		orig_ip_bytes: count      &log &optional;
		resp_pkts:     count      &log &optional;
		resp_ip_bytes: count      &log &optional;
		tunnel_parents: set[string] &log;
	};
}
