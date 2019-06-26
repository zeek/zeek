# @TEST-EXEC-FAIL: zeek -b %INPUT >out 2>&1
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff out
# Record coercion attempt should report mismatched field types.
global wrong = "80/tcp";

type myrec: record {
	cid: conn_id;
};

event zeek_init()
	{
	local mr: myrec;
	mr = [$cid = [$orig_h=1.2.3.4,$orig_p=0/tcp,$resp_h=0.0.0.0,$resp_p=wrong]];
	get_port_transport_proto(mr$cid$resp_p);
	}
