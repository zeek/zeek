# @TEST-EXEC: btest-bg-run zeek zeek -b ../dirtest.zeek
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/next1 10 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: touch testdir/newone
# @TEST-EXEC: rm testdir/bye
# @TEST-EXEC: $SCRIPTS/wait-for-file zeek/next2 10 || (btest-bg-wait -k 1 && false)
# @TEST-EXEC: touch testdir/bye
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: touch testdir/newone
# @TEST-EXEC: btest-diff zeek/.stdout

@TEST-START-FILE dirtest.zeek

@load base/utils/dir
redef exit_only_after_terminate = T;

global c: count = 0;

global initial_files: set[string] = set();

function check_initial_file(s: string)
	{
	if ( s in initial_files )
		print "initial file", s;
	else
		print "didn't see initial file", s;
	}

function new_file(fname: string)
	{
	++c;

	if ( c <= 3 )
		add initial_files[fname];
	else
		print "new_file", fname;

	if ( c == 3 )
		{
		check_initial_file("../testdir/hi");
		check_initial_file("../testdir/howsitgoing");
		check_initial_file("../testdir/bye");
		system("touch next1");
		}
	else if ( c == 4 )
		system("touch next2");
	else if ( c == 5 )
		terminate();
	}

event zeek_init()
	{
	Dir::monitor("../testdir", new_file, .25sec);
	}

@TEST-END-FILE

@TEST-START-FILE testdir/hi
123
@TEST-END-FILE

@TEST-START-FILE testdir/howsitgoing
abc
@TEST-END-FILE

@TEST-START-FILE testdir/bye
!@#
@TEST-END-FILE
