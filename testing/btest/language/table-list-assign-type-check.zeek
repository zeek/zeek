# @TEST-EXEC-FAIL: zeek -b %INPUT >output 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output

event zeek_init()
	{
	# This assignment should pass type-checking.
	local service_table_good: table[string, count] of string = {
	    ["www", 80] = "Internal Web Server",
	    ["dns1", 53] = "Internal DNS 1",
	    ["dns2", 53] = "Internal DNS 2",
	    ["dhcp-for-wifi", 443] = "DHCP Management interface for WiFi"
	};

	# This assignment should fail type-checking due to yield mismatch.
	local service_table_bad_yield: table[string, count] of count = {
	    ["www", 80] = "Internal Web Server",
	    ["dns1", 53] = "Internal DNS 1",
	    ["dns2", 53] = "Internal DNS 2",
	    ["dhcp-for-wifi", 443] = "DHCP Management interface for WiFi"
	};

	# This assignment should fail type-checking due to index mismatch.
	local service_table_bad_index: table[string, count] of string = {
	    ["www", "80"] = "Internal Web Server",
	    ["dns1", "53"] = "Internal DNS 1",
	    ["dns2", "53"] = "Internal DNS 2",
	    ["dhcp-for-wifi", "443"] = "DHCP Management interface for WiFi"
	};

	local test_set_good: set[string] = {"1", "2", "3"};
	local test_set_bad: set[string] = {1, 2, 3};
	}
