# Copyright (c) 2021 by the Zeek Project. See LICENSE for details.

module TFTP;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the request happened.
		ts:		time &log;
		## Unique ID for the connection.
		uid:		string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:		conn_id &log;
		## True  for write requests, False for read request.
		wrq:		bool &log;
		## File name of request.
		fname:		string &log;
		## Mode of request.
		mode:		string &log;
		## UID of data connection
		uid_data:	string &optional &log;
		## Number of bytes sent.
		size:		count &default=0 &log;
		## Highest block number sent.
		block_sent:	count &default=0 &log;
		## Highest block number ackknowledged.
		block_acked:	count &default=0 &log;
		## Any error code encountered.
		error_code:	count &optional &log;
		## Any error message encountered.
		error_msg:	string &optional &log;

		# Set to block number of final piece of data once received.
		final_block: count &optional;

		# Set to true once logged.
		done: bool &default=F;
	};

	## Event that can be handled to access the TFTP logging record.
	global log_tftp: event(rec: Info);
}

# Maps a partial data connection ID to the request's Info record.
global expected_data_conns: table[addr, port, addr] of Info;

redef record connection += {
	tftp: Info &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(TFTP::LOG, [$columns = Info, $ev = log_tftp, $path="tftp"]);
	}

function log_pending(c: connection)
	{
	if ( ! c?$tftp || c$tftp$done )
		return;

	Log::write(TFTP::LOG, c$tftp);
	c$tftp$done = T;
	}

function init_request(c: connection, is_orig: bool, fname: string, mode: string, is_read: bool)
	{
	log_pending(c);

	local info: Info;
	info$ts  = network_time();
	info$uid = c$uid;
	info$id  = c$id;
	info$fname = fname;
	info$mode = mode;
	info$wrq = (! is_read);
	c$tftp = info;

	# The data will come in from a different source port.
	Analyzer::schedule_analyzer(c$id$resp_h, c$id$orig_h, c$id$orig_p, Analyzer::ANALYZER_SPICY_TFTP, 1min);
	expected_data_conns[c$id$resp_h, c$id$orig_p, c$id$orig_h] = info;
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag) &priority=10
	{
	local id = c$id;
	if ( [c$id$orig_h, c$id$resp_p, c$id$resp_h] in expected_data_conns )
		{
		c$tftp = expected_data_conns[c$id$orig_h, c$id$resp_p, c$id$resp_h];
		c$tftp$uid_data = c$uid;
		add c$service["spicy_tftp_data"];
		}
	}

event tftp::read_request(c: connection, is_orig: bool, fname: string, mode: string)
	{
	init_request(c, is_orig, fname, mode, T);
	}

event tftp::write_request(c: connection, is_orig: bool, fname: string, mode: string)
	{
	init_request(c, is_orig, fname, mode, F);
	}

event tftp::data(c: connection, is_orig: bool, block_num: count, data: string)
	{
	if ( ! c?$tftp || c$tftp$done )
		return;

	local info = c$tftp;

	if ( block_num <= info$block_sent )
		# Duplicate (or previous gap; we don't track that)
		return;

	info$size += |data|;
	info$block_sent = block_num;

	if ( |data| < 512 )
		# Last block, per spec.
		info$final_block = block_num;
	}

event tftp::ack(c: connection, is_orig: bool, block_num: count)
	{
	if ( ! c?$tftp || c$tftp$done )
		return;

	local info = c$tftp;

	info$block_acked = block_num;

	if ( block_num <= info$block_acked )
		# Duplicate (or previous gap, we don't track that)
		return;

	info$block_acked = block_num;

	# If it's an ack for the last block, we're done.
	if ( info?$final_block && info$final_block == block_num )
		log_pending(c);
	}

event tftp::error(c: connection, is_orig: bool, code: count, msg: string)
	{
	if ( ! c?$tftp || c$tftp$done )
		return;

	local info = c$tftp;

	info$error_code = code;
	info$error_msg = msg;
	log_pending(c);
	}

event tftp::unknown_opcode(c: connection, is_orig: bool, code: count)
	{
	local info = Weird::Info(
		$uid=c$uid,
		$ts=network_time(),
		$name="unknown_opcode",
		$addl=fmt("%d", code),
		$source="TFTP");
	Weird::weird(info);
	}

event connection_state_remove(c: connection)
	{
	if ( ! c?$tftp || c$tftp$done )
		return;

	log_pending(c);
	}
