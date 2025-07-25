# @TEST-DOC: Test the options that limit string and container lengths with local logging
#
# Limit the individual fields to 5 bytes, but keep the total maximum large enough that it
# will write all of the fields.
# @TEST-EXEC: zeek -b %INPUT -e "redef Log::limit_field_string_bytes = 5"
# @TEST-EXEC: mv test.log string-field-length.log
# @TEST-EXEC: btest-diff string-field-length.log

# Leave the individual field bytes alone, but set the maximum length to where it cuts off
# the second field in the middle of a string.
# @TEST-EXEC: zeek -b %INPUT -e "redef Log::limit_total_string_bytes = 115"
# @TEST-EXEC: mv test.log string-total-length-1.log
# @TEST-EXEC: btest-diff string-total-length-1.log

# Leave the individual field bytes alone, but set the maximum length to where it cuts off
# the first field in the middle of a string. Second field should log empty strings.
# @TEST-EXEC: zeek -b %INPUT -e "redef Log::limit_total_string_bytes = 85"
# @TEST-EXEC: mv test.log string-total-length-2.log
# @TEST-EXEC: btest-diff string-total-length-2.log

# Limit the individual containers to 5 items, but keep the total maximum large enough that
# it will write all of the fields.
# @TEST-EXEC: zeek -b %INPUT -e "redef Log::limit_field_container_elements = 5"
# @TEST-EXEC: mv test.log container-field-elements.log
# @TEST-EXEC: btest-diff container-field-elements.log

# Leave the individual field items alone, but set the maximum length to where it cuts off
# the second field in the middle.
# @TEST-EXEC: zeek -b %INPUT -e "redef Log::limit_total_container_elements = 15"
# @TEST-EXEC: mv test.log container-total-length-1.log
# @TEST-EXEC: btest-diff container-total-length-1.log

# Leave the individual field bytes alone, but set the maximum length to where it cuts off
# the first field in the middle. Second field should log empty strings.
# @TEST-EXEC: zeek -b %INPUT -e "redef Log::limit_total_container_elements = 5"
# @TEST-EXEC: mv test.log container-total-length-2.log
# @TEST-EXEC: btest-diff container-total-length-2.log

module Test;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		strings1: vector of string &log;
		strings2: vector of string &log;
	};
}

redef Broker::disable_ssl = T;

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
