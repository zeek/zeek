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
	redef enum Input::ID += { INPUT };
}

type Idx: record {
	i: int;
};

type Val: record {
	b: bool;
};

global destination1: table[int] of Val = table();
global destination2: table[int] of Val = table();

global done: bool = F;

event bro_init()
{
	# first read in the old stuff into the table...
	Input::create_stream(A::INPUT, [$source="input.log", $autostart=F]);
	Input::add_tablefilter(A::INPUT, [$name="input", $idx=Idx, $val=Val, $destination=destination1, $want_record=F,
				$pred(typ: Input::Event, left: Idx, right: bool) = { return right; }
				]);
	Input::add_tablefilter(A::INPUT, [$name="input2",$idx=Idx, $val=Val, $destination=destination2]);
	
	Input::force_update(A::INPUT);
}

event Input::update_finished(id: Input::ID) {
        if ( done == T ) {
                return;
        }

        done = T;

	if ( 1 in destination1 ) {
		print "VALID";
	}
	if ( 2 in destination1 ) {
		print "VALID";
	}
	if ( !(3 in destination1) ) {
		print "VALID";
	}
	if ( !(4 in destination1) ) {
		print "VALID";
	}
	if ( !(5 in destination1) ) {
		print "VALID";
	}
	if ( !(6 in destination1) ) {
		print "VALID";
	}
	if ( 7 in destination1 ) {
		print "VALID";
	}

	print "MARK";

	if ( 2 in destination2 ) {
		print "VALID";
	}
	if ( 2 in destination2 ) {
		print "VALID";
	}
	if ( 3 in destination2 ) {
		print "VALID";
	}
	if ( 4 in destination2 ) {
		print "VALID";
	}
	if ( 5 in destination2 ) {
		print "VALID";
	}
	if ( 6 in destination2 ) {
		print "VALID";
	}
	if ( 7 in destination2 ) {
		print "VALID";
	}
}
