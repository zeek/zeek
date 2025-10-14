# @TEST-DOC: ZAM memory leak regression test after ZValElement introduction.
#
# @TEST-EXEC: zeek -b -OZAM %INPUT >out
# @TEST-EXEC: btest-diff out

module Test;

type R: record {
	id: conn_id;
};

function x(r: R) {
	print r;
}

event zeek_init()
	{
	local cid = conn_id(
		$orig_h=1.2.3.4,
		$orig_p=1234/tcp,
		$resp_h=5.6.7.8,
		$resp_p=80/tcp,
		$proto=7,
	);
	local r = R($id=cid);

	x([$id=r$id]);
	}

