# This tests Zeek's mechanism to detect circular @loads
#
# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: btest-diff .stderr

@load ./notice

event zeek_init() {
    print("Never run");
}

# Extra files
# @TEST-START-FILE notice.zeek
@load ./cluster

module XNotice;

export {
	type XType: enum {
		Tally,
	};
}
# @TEST-END-FILE

# @TEST-START-FILE cluster.zeek
@load ./notice

module XCluster;
export {
	redef enum XNotice::XType += {
		Second,
	};
}
# @TEST-END-FILE
