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


	print A, enum_to_int(A);
	print B, enum_to_int(B);
	print C, enum_to_int(C);
	print AV, enum_to_int(AV);
	print BV, enum_to_int(BV);
	print CV, enum_to_int(CV);
	}
