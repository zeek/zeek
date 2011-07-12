#
# @TEST-EXEC: btest-bg-run sender bro --pseudo-realtime %INPUT ../sender.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run receiver bro --pseudo-realtime %INPUT ../receiver.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-wait -k 1
# @TEST-EXEC: btest-diff sender/ssh.log
# @TEST-EXEC: btest-diff sender/ssh.failure.log
# @TEST-EXEC: btest-diff sender/ssh.success.log
# @TEST-EXEC: cmp receiver/ssh.log sender/ssh.log
# @TEST-EXEC: cmp receiver/ssh.failure.log sender/ssh.failure.log
# @TEST-EXEC: cmp receiver/ssh.success.log sender/ssh.success.log

# This is the common part loaded by both sender and receiver.
module SSH;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { SSH };

	# Define a record with all the columns the log file can have.
	# (I'm using a subset of fields from ssh-ext for demonstration.)
	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string &optional;
		country: string &default="unknown";
	} &log;
}

event bro_init()
{
	Log::create_stream(SSH, [$columns=Log]);
	Log::add_filter(SSH, [$name="f1", $path="ssh.success", $pred=function(rec: Log): bool { return rec$status == "success"; }]);
}

#####

@TEST-START-FILE sender.bro

module SSH;

@load frameworks/communication/listen-clear

function fail(rec: Log): bool
	{
	return rec$status != "success";
	}

event remote_connection_handshake_done(p: event_peer)
	{
	Log::add_filter(SSH, [$name="f2", $path="ssh.failure", $pred=fail]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	local r: Log = [$t=network_time(), $id=cid, $status="success"];

	# Log something.
	Log::write(SSH, r);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="failure", $country="UK"]);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="success", $country="BR"]);
	Log::write(SSH, [$t=network_time(), $id=cid, $status="failure", $country="MX"]);
	}
@TEST-END-FILE

@TEST-START-FILE receiver.bro

#####

@load frameworks/communication

redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $connect=T, $request_logs=T]
};

@TEST-END-FILE
