##! This script filters the opcode and opcode_name fields from dns.log.

@load base/protocols/dns

redef record DNS::Info$opcode -= { &log };
redef record DNS::Info$opcode_name -= { &log };
