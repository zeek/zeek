#
# @TEST-EXEC: btest-bg-run sender bro --pseudo-realtime %INPUT ../sender.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-run receiver bro --pseudo-realtime %INPUT ../receiver.bro
# @TEST-EXEC: sleep 1
# @TEST-EXEC: btest-bg-wait -k 1
# @TEST-EXEC: btest-diff receiver/ssh.log
# @TEST-EXEC: cmp receiver/ssh.log sender/ssh.log

# Remote version testing all types.

# This is the common part loaded by both sender and receiver.

redef LogAscii::empty_field = "EMPTY";

module SSH;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { SSH };

	type Log: record {
		b: bool;
		i: int;
		e: Log::ID;
		c: count;
		p: port;
		sn: subnet;
		n: net;
		a: addr;
		d: double;
		t: time;
		iv: interval;
		s: string;
		sc: set[count];
		ss: set[string];
		se: set[string];
	};
}

event bro_init()
{
	Log::create_stream(SSH, [$columns=Log]);
}

#####

@TEST-START-FILE sender.bro

module SSH;

@load listen-clear

event remote_connection_handshake_done(p: event_peer)
	{
	local empty_set: set[string];

	Log::write(SSH, [
		$b=T,
		$i=-42,
		$e=SSH,
		$c=21,
		$p=123/tcp,
		$sn=10.0.0.1/24,
		$n=10.0.,
		$a=1.2.3.4,
		$d=3.14,
		$t=network_time(),
		$iv=100secs,
		$s="hurz",
		$sc=set(1,2,3,4),
		$ss=set("AA", "BB", "CC"),
		$se=empty_set
		]);
	}
@TEST-END-FILE

@TEST-START-FILE receiver.bro

#####

@load remote

redef Remote::destinations += {
    ["foo"] = [$host = 127.0.0.1, $connect=T, $request_logs=T]
};

@TEST-END-FILE
