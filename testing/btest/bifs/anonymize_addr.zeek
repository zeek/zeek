# @TEST-DOC: Test the various IP anonymizer methods
#
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stdout
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Basic test for non-prefix-preserving and non-random modes
global orig_addr_anonymization: IPAddrAnonymization = KEEP_ORIG_ADDR;
global resp_addr_anonymization: IPAddrAnonymization = SEQUENTIALLY_NUMBERED;

event zeek_init()
	{
	local a: addr = 1.2.3.4;
	local b: addr = 1.2.3.5;
	local c: addr = 1.2.3.6;

	# Returns a copy of the original address
	print anonymize_addr(a, ORIG_ADDR);

	# Returns sequential IPs starting at 0.0.0.2. The first two are duplicated to
	# ensure they return the same value.
	print anonymize_addr(b, RESP_ADDR);
	print anonymize_addr(b, RESP_ADDR);
	print anonymize_addr(c, RESP_ADDR);
	}

# @TEST-START-NEXT

global orig_addr_anonymization: IPAddrAnonymization = PREFIX_PRESERVING_A50;

event zeek_init()
	{
	local a: subnet = 1.2.3.0/24;
	local b: addr = 1.2.3.4;
	local c: addr = 1.2.10.5;
	local d: addr = 1.3.4.5;

	preserve_subnet(a);
	print anonymize_addr(b, ORIG_ADDR);
	print anonymize_addr(c, ORIG_ADDR);
	print anonymize_addr(d, ORIG_ADDR);
	}

# @TEST-START-NEXT

global orig_addr_anonymization: IPAddrAnonymization = PREFIX_PRESERVING_A50;

event zeek_init()
	{
	local a: addr = 1.2.3.4;

	preserve_prefix(a, 24);
	print anonymize_addr(a, ORIG_ADDR);
	}

# @TEST-START-NEXT

global orig_addr_anonymization: IPAddrAnonymization = RANDOM_MD5;
global resp_addr_anonymization: IPAddrAnonymization = RANDOM_SHA256;

event zeek_init()
	{
	local a: addr = 1.2.3.4;
	local b: addr = 1.2.3.5;

	print anonymize_addr(a, ORIG_ADDR);
	print anonymize_addr(b, ORIG_ADDR);
	print anonymize_addr(a, RESP_ADDR);
	print anonymize_addr(b, RESP_ADDR);
	}
