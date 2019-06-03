#
# @TEST-GROUP: sqlite
#
# @TEST-REQUIRES: which sqlite3
#
# @TEST-EXEC: cat port.sql | sqlite3 port.sqlite
# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

@TEST-START-FILE port.sql
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE port (
'port' integer,
'proto' text
);
INSERT INTO "port" VALUES(5353,'udp');
INSERT INTO "port" VALUES(6162,'tcp');
COMMIT;
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

module A;

type Val: record {
	p: port &type_column="proto";
};

event line(description: Input::EventDescription, tpe: Input::Event, p: port)
	{
	print outfile, p;
	}

event zeek_init()
	{
	local config_strings: table[string] of string = {
		 ["query"] = "select port as p, proto from port;",
	};

	outfile = open("../out");
	Input::add_event([$source="../port", $name="port", $fields=Val, $ev=line, $reader=Input::READER_SQLITE, $want_record=F, $config=config_strings]);
	}

event Input::end_of_data(name: string, source:string)
	{
	print outfile, "End of data";
	close(outfile);
	terminate();
	}
