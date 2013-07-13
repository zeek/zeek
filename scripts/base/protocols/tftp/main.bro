
module TFTP;

export {
	redef enum Log::ID += { LOG };
}

const ports = { 69/udp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	#Log::create_stream(TFTP::LOG, [$columns=Info]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_TFTP, ports);
	}

event tftp_read_request(c: connection, filename: string, trans_type: string)
	{
	print fmt("Read request: %s", filename);
	}

event tftp_write_request(c: connection, filename: string, trans_type: string)
	{
	print fmt("Write request: %s", filename);
	}
