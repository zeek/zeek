# These tests set the InputAscii::path_prefix / InputBinary::path_prefix
# variables to verify that an absolute path prefix gets added correctly
# to relative/path-less input sources.
#
# @TEST-EXEC: cat %INPUT | sed "s|@path_prefix@|$PWD/subdir|" >input.zeek
# @TEST-EXEC: mkdir -p subdir
#
# Note, in the following we'd ideally use %DIR to express the
# additional path, but there's currently a problem in btest with using
# %DIR after TEST-START-NEXT.
#
# @TEST-EXEC: BROPATH=$BROPATH:$TEST_BASE/scripts/base/frameworks/input/path-prefix zeek -b input.zeek >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE subdir/input.data
#fields	ip	tag
127.0.3.1	just
127.0.3.2	some
127.0.3.3	value
@TEST-END-FILE

@load path-prefix-common-table.zeek
redef InputAscii::path_prefix = "@path_prefix@";

event zeek_init()
	{
	Input::add_table([$source="input.data", $name="input", $idx=Idx, $val=Val,
			  $destination=destination, $want_record=F]);
	}

# @TEST-START-NEXT
#
# The same test, but using event streams for input.

@load path-prefix-common-event.zeek
redef InputAscii::path_prefix = "@path_prefix@";

event zeek_init()
	{
        Input::add_event([$source="input.data", $name="input",
			  $fields=Val, $ev=inputev]);
	}

# @TEST-START-NEXT
#
# The same test again, but using file analysis w/ binary readers.

@load path-prefix-common-analysis.zeek
redef InputBinary::path_prefix = "@path_prefix@";

event zeek_init()
	{
	Input::add_analysis([$source="input.data", $name="input"]);
	}
