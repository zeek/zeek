# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

function valid_expire_func_single_index(t: table[string] of count, s: string): interval
	{ return 0secs; }

function valid_expire_func_multi_index(t: table[string, string] of count, s: string, s2: string): interval
	{ return 0secs; }

function valid_expire_func_single_index_any(t: table[string] of count, s: any): interval
	{ return 0secs; }

function valid_expire_func_multi_index_any(t: table[string, string] of count, s: any): interval
	{ return 0secs; }

function invalid_expire_func_no_params(): interval
	{ return 0secs; }

function invalid_expire_func_no_return(t: table[string] of count, s: string)
	{ }

function invalid_expire_func_index_params(t: table[addr,port] of set[addr], s: set[addr, port]): interval
	{ return 0secs; }

event invalid_expire_func_because_its_an_event(t: table[string] of count)
	{ }

hook invalid_expire_func_because_its_a_hook(t: table[string] of count)
	{ }

global invalid_expire_func_because_its_a_number = 3;

global valid1: table[string] of count &expire_func=valid_expire_func_single_index;
global valid2: table[string, string] of count &expire_func=valid_expire_func_multi_index;
global valid3: table[string] of count &expire_func=valid_expire_func_single_index_any;
global valid4: table[string, string] of count &expire_func=valid_expire_func_multi_index_any;

global invalid1: table[string] of count &expire_func=invalid_expire_func_no_params;
global invalid2: table[string] of count &expire_func=invalid_expire_func_no_return;
global invalid3: table[addr, port] of set[addr]=table() &create_expire=1 secs &expire_func=invalid_expire_func_index_params;
global invalid4: table[string] of count &expire_func=invalid_expire_func_because_its_an_event;
global invalid5: table[string] of count &expire_func=invalid_expire_func_because_its_a_hook;
global invalid6: table[string] of count &expire_func=invalid_expire_func_because_its_a_number;
