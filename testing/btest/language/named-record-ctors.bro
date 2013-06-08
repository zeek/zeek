# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

type MyRec: record {
	min: count &optional;
	max: count;
};

local myrec: MyRec = MyRec($max=2);
print myrec;
myrec = MyRec($min=7, $max=42);
print myrec;
