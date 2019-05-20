# @TEST-REQUIRES: which sqlite3
#
# @TEST-EXEC: cat ssh.sql | sqlite3 ssh.sqlite
#
# @TEST-GROUP: sqlite
#
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: sed '1d' .stderr | sort > cmpfile
# @TEST-EXEC: btest-diff cmpfile

@TEST-START-FILE ssh.sql
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE ssh (
'b' boolean,
'i' integer,
'e' text,
'c' integer,
'p' integer,
'sn' text,
'a' text,
'd' double precision,
't' double precision,
'iv' double precision,
's' text,
'sc' text,
'ss' text,
'se' text,
'vc' text,
'vs' text,
'vn' text
);
INSERT INTO "ssh" VALUES(1,-42,'SSH::LOG',21,123,'10.0.0.0/24','1.2.3.4',3.14,1.35837684939385390286e+09,100.0,'hurz','2,4,1,3','CC,AA,BB','(empty)','10,20,30','', null);
COMMIT;
@TEST-END-FILE

redef exit_only_after_terminate = T;

module SSH;

export {
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
		vs: vector of string;
		vh: vector of string &optional;
	} &log;
}


global outfile: file;

event line(description: Input::EventDescription, tpe: Input::Event, p: SSH::Log)
	{
	print outfile, p;

	print outfile, |p$se|;
	print outfile, |p$vs|;
	}

event term_me()
	{
	terminate();
	}

event zeek_init()
	{
	local config_strings: table[string] of string = {
		 ["query"] = "select * from ssh;",
	};
	
	local config_strings2: table[string] of string = {
		 ["query"] = "select b, g, h from ssh;",
	};

	outfile = open("../out");
	Input::add_event([$source="../ssh", $name="ssh", $fields=SSH::Log, $ev=line, $reader=Input::READER_SQLITE, $want_record=T, $config=config_strings]);
	Input::add_event([$source="../ssh", $name="ssh2", $fields=SSH::Log, $ev=line, $reader=Input::READER_SQLITE, $want_record=T, $config=config_strings2]);

	schedule +3secs { term_me() };

	}
