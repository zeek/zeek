# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

module A;

type Color: enum {
	Red = 10,
	White = 20,
	Blue = 30
};

type Foo: record {
	hello: string;
	t: bool;
	f: bool;
	n: count &optional;
	m: count &optional;  # not in input
	def: count &default = 123;
	i: int;
	pi: double;
	a: string_vec;
	c1: Color;
	p: port;
	ti: time;
	it: interval;
	ad: addr;
	s: subnet;
	re: pattern;
	su: subnet_set;
	se: set[addr, port];
};

event zeek_init()
	{
	local json = "{\"hello\":\"world\",\"t\":true,\"f\":false,\"se\":[[\"192.168.0.1\", \"80/tcp\"], [\"2001:db8::1\", \"8080/udp\"]],\"n\":null,\"i\":123,\"pi\":3.1416,\"a\":[\"1\",\"2\",\"3\",\"4\"],\"su\":[\"[aa:bb::0]/32\",\"192.168.0.0/16\"],\"c1\":\"A::Blue\",\"p\":\"1500/tcp\",\"it\":5000,\"ad\":\"127.0.0.1\",\"s\":\"[::1/128]\",\"re\":\"/a/\",\"ti\":1681652265.042767}";
	print from_json(json, Foo);
	}

@TEST-START-NEXT
# argument type mismatch
event zeek_init()
	{
	print from_json("[]", 10);
	}

@TEST-START-NEXT
# JSON parse error
event zeek_init()
	{
	print from_json("{\"hel", string_vec);
	}

@TEST-START-NEXT
type bool_t: bool;
type Foo: record {
	a: bool;
};

# type mismatch error
event zeek_init()
	{
	print from_json("[]", bool_t);
	print from_json("{\"a\": \"hello\"}", Foo);
	}

@TEST-START-NEXT
# type unsupport error
event zeek_init()
	{
	print from_json("[]", table_string_of_string);
	}

@TEST-START-NEXT
type port_t: port;
# additional & incorrect port formats
event zeek_init()
	{
	# Ports can also be given as objects:
	print from_json("{\"port\":80,\"proto\":\"tcp\"}", port_t);
	# These are violations:
	print from_json("\"80\"", port_t);
	print from_json("{}", port_t);
	}

@TEST-START-NEXT
type set_t: set[int, bool];
# index type doesn't match
event zeek_init()
	{
	print from_json("[[1, false], [2]]", set_t);
	print from_json("[[1, false], [2, 1]]", set_t);
	}

@TEST-START-NEXT
type pattern_t: pattern;
# pattern compile error
event zeek_init()
	{
	print from_json("\"/([[:print:]]{-}[[:alnum:]]foo)/\"", pattern_t);
	}

@TEST-START-NEXT
type Color: enum {
	Red = 10
};
# enum error
event zeek_init()
	{
	print from_json("\"Yellow\"", Color);
	}

@TEST-START-NEXT
# container null
event zeek_init()
	{
	print from_json("[\"fe80::/64\",null,\"192.168.0.0/16\"]", subnet_set);
	print from_json("[\"1\",null,\"3\",\"4\"]", string_vec);
	}

@TEST-START-NEXT
type Foo: record {
	hello: string;
	t: bool;
};
# record field null or missing
event zeek_init()
	{
	print from_json("{\"t\":null}", Foo);
	print from_json("{\"hello\": null, \"t\": true}", Foo);
	}

@TEST-START-NEXT
type Foo: record {
	hello: string;
};
# extra fields are alright
event zeek_init()
	{
	print from_json("{\"hello\": \"Hello!\", \"t\": true}", Foo);
	}

@TEST-START-NEXT
type Foo: record {
	id_field: string;
};
# test key_fun for n
event zeek_init()
	{
	print from_json("{\"id-field\": \"Hello!\"}", Foo);
	print from_json("{\"id-field\": \"Hello!\"}", Foo, function(s: string): string {
		return gsub(s, /[^a-zA-Z0-9_]/, "_");
	});
	}

@TEST-START-NEXT
# From: https://www.rfc-editor.org/rfc/rfc8520#section-9
global input:string = "{\"ietf-mud:mud\":{\"mud-version\":1,\"mud-url\":\"https://lighting.example.com/lightbulb2000\",\"last-update\":\"2019-01-28T11:20:51+01:00\",\"cache-validity\":48,\"is-supported\":true,\"systeminfo\":\"The BMS Example Light Bulb\",\"from-device-policy\":{\"access-lists\":{\"access-list\":[{\"name\":\"mud-76100-v6fr\"}]}},\"to-device-policy\":{\"access-lists\":{\"access-list\":[{\"name\":\"mud-76100-v6to\"}]}}},\"ietf-access-control-list:acls\":{\"acl\":[{\"name\":\"mud-76100-v6to\",\"type\":\"ipv6-acl-type\",\"aces\":{\"ace\":[{\"name\":\"cl0-todev\",\"matches\":{\"ipv6\":{\"ietf-acldns:src-dnsname\":\"test.example.com\",\"protocol\":6},\"tcp\":{\"ietf-mud:direction-initiated\":\"from-device\",\"source-port\":{\"operator\":\"eq\",\"port\":443}}},\"actions\":{\"forwarding\":\"accept\"}}]}},{\"name\":\"mud-76100-v6fr\",\"type\":\"ipv6-acl-type\",\"aces\":{\"ace\":[{\"name\":\"cl0-frdev\",\"matches\":{\"ipv6\":{\"ietf-acldns:dst-dnsname\":\"test.example.com\",\"protocol\":6},\"tcp\":{\"ietf-mud:direction-initiated\":\"from-device\",\"destination-port\":{\"operator\":\"eq\",\"port\":443}}},\"actions\":{\"forwarding\":\"accept\"}}]}}]}}";

module Mud8520;
type MudAccessList: record {
	name: string;
};

type MudAccessLists: record {
	access_list: vector of MudAccessList;
};

type MudPolicy: record {
	access_lists: MudAccessLists;
};

type MudMatchPort: record {
	operator: string;
	_port: count;
};

type MudMatch: record {
	ietf_acldns_dst_dnsname: string &optional;
	ietf_mud_direction_initiated: string &optional;
	destination_port: MudMatchPort &optional;
};

type MudMatches: record {
	# Might make more sense to have individual types.
	ipv6: MudMatch &optional;
	tcp: MudMatch &optional;
};

type MudAce: record {
	name: string;
	matches: MudMatches;
};

type MudAces: record {
	ace: vector of MudAce;
};

type MudAcl: record {
	name: string;
	_type: string;
	aces: MudAces;
};
type MudAcls: record {
	acl: vector of MudAcl;
};

type Mud: record {
	mud_version: count;
	mud_url: string;
	last_update: string;
	cache_validity: count;
	is_supported: bool;
	systeminfo: string;
	from_device_policy: MudPolicy;
	to_device_policy: MudPolicy;
};

type MudDocument: record {
	ietf_mud_mud: Mud;
	ietf_access_control_list_acls: MudAcls;
};

event zeek_init()
	{
	local mud_mapping_table: table[string] of string = {
		["type"] = "_type",
		["port"] = "_port",
	};
	local mud_json_key_fun = function [mud_mapping_table](s: string): string {
		if ( s in mud_mapping_table )
			return mud_mapping_table[s];
		return gsub(s, /[^a-zA-Z0-9_]/, "_");
	};

	local result = from_json(input, MudDocument, mud_json_key_fun);
	print result$valid;
	print result$v;
	}
