# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

# Ok, this one tests a fun case.
# Input file contains two lines mapping to the same index, but with different values,
# where the predicate accepts the first one and refuses the second one.
# Desired result -> first entry stays.

@TEST-START-FILE input.log
#fields	restriction	guid	severity	confidence	detecttime	address	protocol	portlist	asn	prefix	rir	cc	impact	description	alternativeid_restriction	alternativeid
need-to-know	8c864306-d21a-37b1-8705-746a786719bf	medium	65	1342656000	1.0.17.227	-	-	2519 VECTANT VECTANT Ltd.	1.0.16.0/23	apnic	JP	spam infrastructure	spamming	public	http://reputation.alienvault.com/reputation.generic
need-to-know	8c864306-d21a-37b1-8705-746a786719bf	medium	95	1342569600	1.228.83.33	6	25	9318 HANARO-AS Hanaro Telecom Inc.	1.224.0.0/13	apnic	KR	spam infrastructure	direct ube sources, spam operations & spam services	public	http://www.spamhaus.org/query/bl?ip=1.228.83.33
need-to-know	8c864306-d21a-37b1-8705-746a786719bf	medium	65	1342656000	1.228.83.33	-	-	9318 HANARO-AS Hanaro Telecom Inc.	1.224.0.0/13	apnic	KR	spam infrastructure	spamming;malware domain	public	http://reputation.alienvault.com/reputation.generic
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

type Idx: record {
	address: addr;
};

type Val: record {
	asn: string;
	severity: string;
	confidence: count;
	detecttime: time;
};

global servers: table[addr] of Val = table();

event zeek_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input.log", $name="input", $idx=Idx, $val=Val, $destination=servers,
				$pred(typ: Input::Event, left: Idx, right: Val) = { if ( right$confidence > 90 ) { return T; } return F; }
				]);
	}

event Input::end_of_data(name: string, source: string)
	{
	print outfile, servers;
	Input::remove("input");
	close(outfile);
	terminate();
	}
