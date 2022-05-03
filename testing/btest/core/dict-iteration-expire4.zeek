# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek --load-seeds 1.seeds -Cr - %INPUT
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek --load-seeds 2.seeds -Cr - %INPUT
# @TEST-DOC:  Regression test #2032; no output check, just shouldn't crash

redef table_expire_delay = 0.1sec;
redef table_incremental_step = 10;
redef table_expire_interval = 0.01sec;

# redef exit_only_after_terminate = T;

type Key: record {
  c: count;
  s1: string;
  s2: string;
  a1: addr;
  a2: addr;
};

global insert_many: event(n: count);
global insert_many_f: function(n: count);

function expire(t: table[Key] of Key, k: Key): interval {
  print(fmt("Expiring %s sz=%s", k, |t|));
  schedule 0.2sec { insert_many(2 * |t| + 8) };
  #insert_many_f(2 * |t| + 8);
  return 0sec;
}

global tbl: table[Key] of Key &create_expire=0.1sec &expire_func=expire;

function make_key(i: count): Key {
  return Key(
    $c=i,
    $s1=cat(i),
    $s2=cat(2 * i),
    $a1=count_to_v4_addr(1000000 + i),
    $a2=count_to_v4_addr(2000000 + i)
  );
}

event insert_many(n: count) {
  local i = n;
  while (++i < n + 37) {
    local k = make_key(i);
    tbl[k] = k;
  }
}

function insert_many_f(n: count) {
  local i = n;
  while (++i < n + 37) {
    local k = make_key(i);
    tbl[k] = k;
  }
}

event zeek_init() {
 local k = make_key(1);
 tbl[k] = k;
}

@TEST-START-FILE 1.seeds
3569182667
3864322632
2737717875
4292737228
959594593
3440781012
1483058089
950202215
611472157
2218394723
3885890563
1396441520
1851988456
3540954895
2626085489
3793122452
3535210719
936980445
3834222442
2355333979
113403102
@TEST-END-FILE

@TEST-START-FILE 2.seeds
4013930712
1835775324
3393047106
3151534432
2727962940
3990820447
792628001
3844857817
2661636943
2621115293
2909873159
3909343487
1003041063
1365337823
2042927118
3623503659
394335333
302877509
348858887
14638654
4267481449
@TEST-END-FILE
