#
# @TEST-EXEC: bro %INPUT >out
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input.log
#separator \x09
#path	ssh
#fields	i	b	
#types	int	bool
1	T
2	T
3	F
4	F
5	F
6	F
7	T
@TEST-END-FILE

redef InputAscii::empty_field = "EMPTY";

module A;

export {
	redef enum Log::ID += { LOG };
}

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
};

global servers: table[int] of Val = table();

event bro_init()
{
	# first read in the old stuff into the table...
	Input::create_stream(A::LOG, [$source="input.log"]);
	Input::add_tablefilter(A::LOG, [$name="input", $idx=Idx, $val=Val, $destination=servers, $want_record=F,
				$pred(typ: Input::Event, left: Idx, right: bool) = { return right; }
				]);
	Input::force_update(A::LOG);
	if ( 1 in servers ) {
		print "VALID";
	}
	if ( 2 in servers ) {
		print "VALID";
	}
	if ( !(3 in servers) ) {
		print "VALID";
	}
	if ( !(4 in servers) ) {
		print "VALID";
	}
	if ( !(5 in servers) ) {
		print "VALID";
	}
	if ( !(6 in servers) ) {
		print "VALID";
	}
	if ( 7 in servers ) {
		print "VALID";
	}
}
