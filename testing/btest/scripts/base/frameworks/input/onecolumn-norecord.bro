#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	b	i	
#types	bool	int
T	-42	
@TEST-END-FILE

redef InputAscii::empty_field = "EMPTY";

module A;

export {
	redef enum Log::ID += { LOG };
}

type idx: record {
	i: int;
};

type val: record {
	b: bool;
};

global servers: table[int] of val = table();

event bro_init()
{
	# first read in the old stuff into the table...
	Input::create_stream(A::LOG, [$source="input.log"]);
	Input::add_tablefilter(A::LOG, [$name="input", $idx=idx, $val=val, $destination=servers, $want_record=F]);
	Input::force_update(A::LOG);
	print servers;
}
