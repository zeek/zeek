# These tests verify that when setting neither InputAscii::path_prefix
# nor InputBinary::path_prefix, Zeek correctly locates local input files.
#
# @TEST-EXEC: BROPATH=$BROPATH:$TEST_BASE/scripts/base/frameworks/input/path-prefix zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

@TEST-START-FILE input.data
#fields	ip	tag
127.0.0.1	just
127.0.0.2	some
127.0.0.3	value
@TEST-END-FILE

@load path-prefix-common-table.zeek

event zeek_init()
	{
	Input::add_table([$source="input.data", $name="input", $idx=Idx, $val=Val,
			  $destination=destination, $want_record=F]);
	}

# @TEST-START-NEXT
#
# The same test, but using event streams for input.

@load path-prefix-common-event.zeek

event zeek_init()
	{
        Input::add_event([$source="input.data", $name="input",
                          $fields=Val, $ev=inputev]);
	}

# @TEST-START-NEXT
#
# The same test again, but using file analysis w/ binary readers.

@load path-prefix-common-analysis.zeek

event zeek_init()
	{
	Input::add_analysis([$source="input.data", $name="input"]);
	}
