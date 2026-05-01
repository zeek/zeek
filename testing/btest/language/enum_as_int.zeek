#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

export {
	type test_enum: enum {
		A,
		B,
		C,
	};

	type test_enum_with_val: enum {
		AV = 0xA,
		BV = 0xB,
		CV = 0xC,
	};
}

event zeek_init()
	{
	print A, A as int;
	print B, B as int;
	print C, C as int;
	print AV, AV as int;
	print BV, BV as int;
	print CV, CV as int;

	print A as int != B as int;
	print A as int != C as int;
	print B as int != C as int;
	print A as int < B as int;
	print A as int < C as int;
	print B as int < C as int;

	print AV as int != BV as int;
	print AV as int != CV as int;
	print BV as int != CV as int;
	print AV as int < BV as int;
	print AV as int < CV as int;
	print BV as int < CV as int;
	}
