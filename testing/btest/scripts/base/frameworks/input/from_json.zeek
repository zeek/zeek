# @TEST-DOC: Reading a jsonl file using the raw input reader and parsing via from_json()
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff out

@TEST-START-FILE denylist.jsonl
{"ip": "192.168.0.1", "source": "local", "timestamp": "1990-09-22T12:13:14"}
{"ip": "192.168.0.1", "source": "local", "timestamp": "1990-09-23T13:14:15"}
{"ip": "192.168.0.2", "source": "local"}
{"source": "local"}
{... ]
{"ip": "8.8.4.4", "source": "remote"}
@TEST-END-FILE

redef exit_only_after_terminate = T;

module A;

type Line: record {
	l: string;
};

type Deny: record {
	ip: addr;
	source: string;
	timestamp: string &optional;
	timestamp_parsed: time &optional;
};

event line(description: Input::EventDescription, tpe: Input::Event, line: string)
	{
	local r = from_json(line, Deny);
	if ( r$valid )
		{
		local deny = r$v as Deny;
		if ( deny?$timestamp )
			deny$timestamp_parsed = strptime("%Y-%m-%dT%H:%M:%S", deny$timestamp);

		print fmt("Valid: %s (%s)", deny, line);
		}
	else
		print fmt("Invalid: '%s'", line);
	}

event die()
	{
	if ( zeek_is_terminating() )
		return;

	print "error: test timeout";
	exit(1);
	}

event zeek_init()
	{
	Input::add_event([
		$source="denylist.jsonl",
		$name="denylist",
		$reader=Input::READER_RAW,
		$fields=Line,
		$ev=line,
		$want_record=F
	]);

	schedule 5sec { die() };
	}

event Input::end_of_data(name: string, source:string)
	{
	Input::remove("deny");
	terminate();
	}
