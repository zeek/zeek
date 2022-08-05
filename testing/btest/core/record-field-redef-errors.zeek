# @TEST-DOC: redef record Record$field testing
# @TEST-EXEC-FAIL: zeek -b setup.zeek %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

# Bad syntax
redef record M::Info$ts -= &log;

@TEST-START-NEXT
# Really bad syntax
redef record M::Info$ts -= { &log;

@TEST-START-NEXT
# Not the right syntax
redef record M::Info$ts -= [ &log ];

@TEST-START-NEXT
# Can not make something optional
redef record M::Info$ts += { &optional };

@TEST-START-NEXT
# Can not add &default
redef record M::Info$addl += { &log &default="default"};

@TEST-START-NEXT
# Can not remove optional
redef record M::Info$msg -= { &log &optional };

@TEST-START-NEXT
# Not a record
redef record M::ErrCode$msg += { &log };

@TEST-START-NEXT
redef record M::Unknown$ts += { &log };

@TEST-START-NEXT
redef record M::Unknown$ts -= { &log };

@TEST-START-NEXT
redef record M::Info$no_such_field += { &log };

@TEST-START-NEXT
redef record M::Info$no_such_field -= { &log };

@TEST-START-NEXT
# This isn't reported very nicely: It's a syntax error rather than an unknown attribute
redef record M::Info$ts += { &unknown };

# @TEST-START-FILE setup.zeek
module M;
export {
	type ErrCode: enum {
		ECONFUSING,
	};

	type Info: record {
		ts:   time   &log;
		peer: string &log &default="zeek";
		msg:  string &log &optional;
		addl: string &optional;
		noattrs: string;
	};
}
# @TEST-END-FILE
