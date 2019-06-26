# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b -r $TRACES/wikipedia.trace %INPUT
# @TEST-EXEC: btest-bg-wait 60

function test_basic_bloom_filter()
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

  # Alternative constructor.
  local bf_dbl = bloomfilter_basic_init2(4, 10);
  bloomfilter_add(bf_dbl, 4.2);
  bloomfilter_add(bf_dbl, 3.14);
  print bloomfilter_lookup(bf_dbl, 4.2);
  print bloomfilter_lookup(bf_dbl, 3.14);

  # Basic usage with strings.
  local bf_str = bloomfilter_basic_init(0.9, 10);
  bloomfilter_add(bf_str, "foo");
  bloomfilter_add(bf_str, "bar");
  print bloomfilter_lookup(bf_str, "foo");
  print bloomfilter_lookup(bf_str, "bar");
  print bloomfilter_lookup(bf_str, "bazzz"), "fp"; # FP
  print bloomfilter_lookup(bf_str, "quuux"), "fp"; # FP
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

  # Merging
  local bf_cnt2 = bloomfilter_basic_init(0.1, 1000);
  bloomfilter_add(bf_cnt2, 42);
  bloomfilter_add(bf_cnt, 100);
  local bf_merged = bloomfilter_merge(bf_cnt, bf_cnt2);
  print bloomfilter_lookup(bf_merged, 42);
  print bloomfilter_lookup(bf_merged, 84);
  print bloomfilter_lookup(bf_merged, 100);
  print bloomfilter_lookup(bf_merged, 168);

  #empty filter tests
  local bf_empty = bloomfilter_basic_init(0.1, 1000);
  local bf_empty_merged = bloomfilter_merge(bf_merged, bf_empty);
  print bloomfilter_lookup(bf_empty_merged, 42);
  }

function test_counting_bloom_filter()
  {
  local bf = bloomfilter_counting_init(3, 32, 3);
  bloomfilter_add(bf, "foo");
  print bloomfilter_lookup(bf, "foo");    # 1
  bloomfilter_add(bf, "foo");
  print bloomfilter_lookup(bf, "foo");    # 2
  bloomfilter_add(bf, "foo");
  print bloomfilter_lookup(bf, "foo");    # 3
  bloomfilter_add(bf, "foo");
  print bloomfilter_lookup(bf, "foo");    # still 3


  bloomfilter_add(bf, "bar");
  bloomfilter_add(bf, "bar");
  print bloomfilter_lookup(bf, "bar");    # 2
  print bloomfilter_lookup(bf, "foo");    # still 3

  # Merging
  local bf2 = bloomfilter_counting_init(3, 32, 3);
  bloomfilter_add(bf2, "baz");
  bloomfilter_add(bf2, "baz");
  bloomfilter_add(bf2, "bar");
  local bf_merged = bloomfilter_merge(bf, bf2);
  print bloomfilter_lookup(bf_merged, "foo");
  print bloomfilter_lookup(bf_merged, "bar");
  print bloomfilter_lookup(bf_merged, "baz");
  }

event new_connection(c: connection)
  {
  test_basic_bloom_filter();
  test_counting_bloom_filter();
  }
