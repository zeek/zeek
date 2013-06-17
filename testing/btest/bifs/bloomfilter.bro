# @TEST-EXEC: bro -b %INPUT >output
# @TEST-EXEC: btest-diff output

event bro_init()
  {
  # Basic usage with counts.
  local bf_cnt = bloomfilter_basic_init(0.1, 1000);
  bloomfilter_add(bf_cnt, 42);
  bloomfilter_add(bf_cnt, 84);
  bloomfilter_add(bf_cnt, 168);
  print bloomfilter_lookup(bf_cnt, 0);
  print bloomfilter_lookup(bf_cnt, 42);
  print bloomfilter_lookup(bf_cnt, 168);
  print bloomfilter_lookup(bf_cnt, 336);
  bloomfilter_add(bf_cnt, 0.5); # Type mismatch
  bloomfilter_add(bf_cnt, "foo"); # Type mismatch

  # Basic usage with strings.
  local bf_str = bloomfilter_basic_init(0.9, 10);
  bloomfilter_add(bf_str, "foo");
  bloomfilter_add(bf_str, "bar");
  print bloomfilter_lookup(bf_str, "foo");
  print bloomfilter_lookup(bf_str, "bar");
  print bloomfilter_lookup(bf_str, "b4z"); # FP
  print bloomfilter_lookup(bf_str, "quux"); # FP
  bloomfilter_add(bf_str, 0.5); # Type mismatch
  bloomfilter_add(bf_str, 100); # Type mismatch

  # Edge cases.
  local bf_edge0 = bloomfilter_basic_init(0.000000000001, 1);
  local bf_edge1 = bloomfilter_basic_init(0.00000001, 100000000);
  local bf_edge2 = bloomfilter_basic_init(0.9999999, 1);
  local bf_edge3 = bloomfilter_basic_init(0.9999999, 100000000000);

  # Invalid parameters.
  local bf_bug0 = bloomfilter_basic_init(-0.5, 42);
  local bf_bug1 = bloomfilter_basic_init(1.1, 42);
  }
