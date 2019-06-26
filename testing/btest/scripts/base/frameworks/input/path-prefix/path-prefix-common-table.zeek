# @TEST-IGNORE
#
# This file contains code used by the table-driven path-prefix tests.

redef exit_only_after_terminate = T;

type Idx: record {
	ip: addr;
};

type Val: record {
	tag: string;
};

global destination: table[addr] of string = table();

event Input::end_of_data(name: string, source: string)
	{
	print destination;
	terminate();
	}
