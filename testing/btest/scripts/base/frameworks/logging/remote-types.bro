# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run sender bro -B threading,logging --pseudo-realtime %INPUT ../sender.bro
# @TEST-EXEC: btest-bg-run receiver bro -B threading,logging --pseudo-realtime %INPUT ../receiver.bro
# @TEST-EXEC: btest-bg-wait -k 10
# @TEST-EXEC: btest-diff receiver/test.log
# @TEST-EXEC: cat receiver/test.log | egrep -v '#open|#close' >r.log
# @TEST-EXEC: cat sender/test.log   | egrep -v '#open|#close' >s.log
# @TEST-EXEC: cmp r.log s.log

# Remote version testing all types.

# This is the common part loaded by both sender and receiver.

redef LogAscii::empty_field = "EMPTY";

module Test;

export {
	# Create a new ID for our log stream
	redef enum Log::ID += { LOG };

	type Log: record {
		b: bool;
		i: int;
		e: Log::ID;
		c: count;
		p: port;
		sn: subnet;
		a: addr;
		d: double;
		t: time;
		iv: interval;
		s: string;
		sc: set[count];
		ss: set[string];
		se: set[string];
		vc: vector of count;
		ve: vector of string;
	} &log;
}

event bro_init()
{
	Log::create_stream(Test::LOG, [$columns=Log]);
}

#####

@TEST-START-FILE sender.bro

module Test;

@load frameworks/communication/listen

event remote_connection_handshake_done(p: event_peer)
	{
	local empty_set: set[string];
	local empty_vector: vector of string;

	Log::write(Test::LOG, [
		$b=T,
		$i=-42,
		$e=Test::LOG,
		$c=21,
		$p=123/tcp,
		$sn=10.0.0.1/24,
		$a=1.2.3.4,
		$d=3.14,
		$t=network_time(),
		$iv=100secs,
		$s="hurz",
		$sc=set(1,2,3,4),
		$ss=set("AA", "BB", "CC"),
		$se=empty_set,
		$vc=vector(10, 20, 30),
		$ve=empty_vector
		]);
	disconnect(p);
	}
@TEST-END-FILE

@TEST-START-FILE receiver.bro

#####

redef Communication::nodes += {
    ["foo"] = [$host = 127.0.0.1, $connect=T, $request_logs=T]
};

@TEST-END-FILE
