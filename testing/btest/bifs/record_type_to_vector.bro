#
# @TEST-EXEC: bro -b %INPUT >out
# @TEST-EXEC: btest-diff out

type myrecord: record {
  ct: count;
  str1: string;
};

event bro_init()
	{
	print record_type_to_vector("myrecord");
	}
