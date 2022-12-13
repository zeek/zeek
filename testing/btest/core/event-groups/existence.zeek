# @TEST-DOC: Test for has_module_events and has_event_group
# @TEST-EXEC: zeek -b %INPUT > output
# @TEST-EXEC: btest-diff output

module TestMyProtocol::Logging;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {}

module TestMyProtocol;

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &group="test-my-protocol" {}

module Test;

function assert_expected(msg: string, expected: bool, actual: bool)
	{
	local prefix = expected == actual ? "PASS" : "FAIL";
	print fmt("%s: %s (%s == %s)", prefix, msg, expected, actual);
	}

event zeek_init()
	{
	assert_expected("eg: has test-my-protocol", T, has_event_group("test-my-protocol"));
	assert_expected("eg: has not test-my-protocol-nope", F, has_event_group("test-my-protocol-nope"));
	assert_expected("eg: has not eg TestMyProtocol::Logging", F, has_event_group("TestMyProtocol::Logging"));

	assert_expected("me: has TestMyProtocol::Logging", T, has_module_events("TestMyProtocol::Logging"));
	assert_expected("me: has not test-my-protocol", F, has_module_events("test-my-protocol"));
	}
