# These tests set the InputAscii::path_prefix / InputBinary::path_prefix
# variables to verify that setting these prefixes has no effect when
# an input file uses an absolute-path source.
#
# @TEST-EXEC: cat %INPUT | sed "s|@path_prefix@|$PWD|" >input.zeek
# @TEST-EXEC: BROPATH=$BROPATH:$TEST_BASE/scripts/base/frameworks/input/path-prefix zeek -b input.zeek >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE input.data
#fields	ip	tag
127.0.4.1	just
127.0.4.2	some
127.0.4.3	value
@TEST-END-FILE

@load path-prefix-common-table.zeek
redef InputAscii::path_prefix = "/this/does/not/exist";

event zeek_init()
	{
	Input::add_table([$source="@path_prefix@/input.data", $name="input", $idx=Idx, $val=Val,
			  $destination=destination, $want_record=F]);
	}

# @TEST-START-NEXT
#
# The same test, but using event streams for input.

@load path-prefix-common-event.zeek
redef InputAscii::path_prefix = "/this/does/not/exist";

event zeek_init()
	{
        Input::add_event([$source="@path_prefix@/input.data", $name="input",
			  $fields=Val, $ev=inputev]);
	}

# @TEST-START-NEXT
#
# The same test again, but using file analysis w/ binary readers.

@load path-prefix-common-analysis.zeek
redef InputBinary::path_prefix = "/this/does/not/exist";

event zeek_init()
	{
	Input::add_analysis([$source="@path_prefix@/input.data", $name="input"]);
	}
