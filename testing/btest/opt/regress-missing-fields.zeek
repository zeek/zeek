# @TEST-DOC: Regression test for specialized operations checking for missing record fields
# @TEST-REQUIRES: test "${ZEEK_USE_CPP}" != "1"
# @TEST-EXEC: zeek -O ZAM -b %INPUT >error-messages 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff error-messages

@load base/utils/conn-ids.zeek

event zeek_init()
	{
	local id: conn_id; # not initialized!
	print id_string(id);
	}

# Testing for ZAM specialized operation for adding multiple record fields.
type R1: record {
	v1: count &optional;
	v2: count &optional;
	v3: count &optional;
	v4: count &optional;
};

event zeek_init()
	{
	local l1: R1;
	local l2: R1;

	# Both LHS and RHS are uninitialized, so use the same fields
	# because we don't presuppose which one generates the error first.
	l2$v1 += l1$v1;
	l2$v2 += l1$v2; # We never get here
	}

event zeek_init()
	{
	local l1 = R1($v1 = 1);
	local l2: R1;

	# Should report v3, since v1 is good-to-go.
	l2$v3 += l1$v1;
	l2$v2 += l1$v2; # We never get here
	}

event zeek_init()
	{
	local l1: R1;
	local l2 = R1($v1 = 1);

	# Should report v4, since v1 is good-to-go.
	l2$v1 += l1$v4;
	l2$v2 += l1$v2; # We never get here
	}

# Testing for ZAM specialized operation for assigning multiple record fields.
type R2: record {
	vv1: vector of count &optional;
	vv2: vector of count &optional;
};

event zeek_init()
	{
	local l1: R2;
	local l2: R2;

	l2$vv1 = l1$vv1;
	l2$vv2 = l1$vv2; # We don't get here
	}

event zeek_init()
	{
	local l1 = R2($vv1 = vector());
	local l2: R2;

	l2$vv1 = l1$vv1;
	l2$vv2 = l1$vv2; # We should get here, but then fail
	}
