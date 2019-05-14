# @TEST-EXEC: zeek -b %INPUT global_hash_seed="foo" >>output
# @TEST-EXEC: zeek -b %INPUT global_hash_seed="my_seed" >>output 
# @TEST-EXEC: btest-diff output

type Foo: record 
	{
	a: count;
	b: string;
	};

function test_bloom_filter()
  {
  local bf1 = bloomfilter_basic_init(0.9, 10);
  bloomfilter_add(bf1, "foo");
  bloomfilter_add(bf1, "bar");
  
  local bf2 = bloomfilter_basic_init(0.9, 10);
  bloomfilter_add(bf2, Foo($a=1, $b="xx"));
  bloomfilter_add(bf2, Foo($a=2, $b="yy"));
  
  local bf3 = bloomfilter_basic_init(0.9, 10, "my_seed");
  bloomfilter_add(bf3, "foo");
  bloomfilter_add(bf3, "bar");
  
  local bf4 = bloomfilter_basic_init(0.9, 10, "my_seed");
  bloomfilter_add(bf4, Foo($a=1, $b="xx"));
  bloomfilter_add(bf4, Foo($a=2, $b="yy"));

  print "bf1, global_seed", bloomfilter_internal_state(bf1);
  print "bf2, global_seed", bloomfilter_internal_state(bf2);
  print "bf3, my_seed",     bloomfilter_internal_state(bf3);
  print "bf4, my_seed",     bloomfilter_internal_state(bf4);

  
  }

event zeek_init()
  {
  test_bloom_filter();
  }
