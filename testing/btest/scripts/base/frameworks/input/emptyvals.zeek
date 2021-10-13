# This test verifies the handling of unset fields in input files.
# For table indexes, columns wwith undefined fields cannot work
# and are skipped. For values, unset fields are safe for the user
# only when those fields are defined &optional, otherwise they
# too are skipped.

# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff out

@TEST-START-FILE input1.log
#separator \x09
#path	ssh
#fields	b	i
##types	bool	int
T	1
-	2
F	-
@TEST-END-FILE

@TEST-START-FILE input2.log
#separator \x09
#path	ssh
#fields	b	i	j
##types	bool	int	int
T	1	1
-	2	2
F	-	3
@TEST-END-FILE

redef exit_only_after_terminate = T;

global outfile: file;

redef InputAscii::empty_field = "EMPTY";

module A;

# We use two different index records just because the internal code
# paths differ slightly for these. And one used to crash. :)
type Idx1: record {
	i: int;
};

type Idx2: record {
	i: int;
	j: int;
};

type ValReq: record {
	b: bool;
};

type ValOpt: record {
	b: bool &optional;
};

global servers1: table[int] of ValReq = table();
global servers2: table[int, int] of ValOpt = table();

# Counter to track when we're ready to report both table's contents in
# pre-defined order.
global reads_done = 0;

event zeek_init()
	{
	outfile = open("../out");
	# first read in the old stuff into the table...
	Input::add_table([$source="../input1.log", $name="ssh1", $idx=Idx1, $val=ValReq, $destination=servers1]);
	Input::add_table([$source="../input2.log", $name="ssh2", $idx=Idx2, $val=ValOpt, $destination=servers2]);
	}

event Input::end_of_data(name: string, source:string)
	{
	reads_done += 1;
	if ( reads_done < 2 )
		return;

	print outfile, servers1;
	print outfile, servers2;

	Input::remove("ssh1");
	Input::remove("ssh2");

	close(outfile);
	terminate();
	}
