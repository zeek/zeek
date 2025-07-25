# @TEST-DOC: Test the options that limit string and container lengths when logging
#
# @TEST-EXEC: zeek -b test.zeek %INPUT
# @TEST-EXEC: btest-diff test.log

# @TEST-START-FILE test.zeek

module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		strings1: vector of string &log;
		strings2: vector of string &log;
	};
}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="test"]);

	local rec = Test::Info();
	local i = 0;

	# Create two vectors containing 10 strings with 10 characters each.
	# This leaves us with 200 total characters to work with.
	while ( ++i <= 10 )
		{
		rec$strings1 += "ABCDEFGHIJ";
		rec$strings2 += "ABCDEFGHIJ";
		}

	Log::write(Test::LOG, rec);
	}


# @TEST-END-FILE test.zeek

# Limit the individual fields to 5 bytes, but keep the total maximum large enough that it
# will write all of the fields.
redef Log::max_field_string_bytes = 5;

# @TEST-START-NEXT

# Leave the individual field bytes alone, but set the maximum length to where it cuts off
# the second field in the middle of a string.
redef Log::max_total_string_bytes = 115;

# @TEST-START-NEXT

# Leave the individual field bytes alone, but set the maximum length to where it cuts off
# the first field in the middle of a string. Second field should log empty strings.
redef Log::max_total_string_bytes = 85;

# @TEST-START-NEXT

# Limit the individual containers to 5 items, but keep the total maximum large enough that
# it will write all of the fields.
redef Log::max_field_container_elements = 5;

# @TEST-START-NEXT

# Leave the individual field items alone, but set the maximum length to where it cuts off
# the second field in the middle.
redef Log::max_total_container_elements = 15;

# @TEST-START-NEXT

# Leave the individual field bytes alone, but set the maximum length to where it cuts off
# the first field in the middle. Second field should log empty containers.
redef Log::max_total_container_elements = 5;
