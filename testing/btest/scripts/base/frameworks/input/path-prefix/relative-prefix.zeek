# This test sets the InputAscii::path_prefix / InputBinary::path_prefix
# variables to verify that a relative path prefix applies correctly
# from the current working directory.
#
# @TEST-EXEC: mkdir -p alternative
# @TEST-EXEC: BROPATH=$BROPATH:$TEST_BASE/scripts/base/frameworks/input/path-prefix zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE alternative/input.data
#fields	ip	tag
127.0.1.1	just
127.0.1.2	some
127.0.1.3	value
@TEST-END-FILE

@load path-prefix-common-table.zeek
redef InputAscii::path_prefix = "alternative";

event zeek_init()
	{
	Input::add_table([$source="input.data", $name="input", $idx=Idx, $val=Val,
			  $destination=destination, $want_record=F]);
	}

# @TEST-START-NEXT
#
# The same test, but using event streams for input.

@load path-prefix-common-event.zeek
redef InputAscii::path_prefix = "alternative";

event zeek_init()
	{
        Input::add_event([$source="input.data", $name="input",
                          $fields=Val, $ev=inputev]);
	}

# @TEST-START-NEXT
#
# The same test again, but using file analysis w/ binary readers.

@load path-prefix-common-analysis.zeek
redef InputBinary::path_prefix = "alternative";

event zeek_init()
	{
	Input::add_analysis([$source="input.data", $name="input"]);
	}
