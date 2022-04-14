# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek --load-seeds 1.seeds -Cr - %INPUT
# @TEST-EXEC: zcat <$TRACES/echo-connections.pcap.gz | zeek --load-seeds 2.seeds -Cr - %INPUT
# @TEST-DOC:  Regression test #2032; no output check, just shouldn't crash

redef table_expire_delay = 0.0001sec;
redef table_incremental_step = 1;
redef table_expire_interval = 0.001sec;


function expire(t: table[conn_id] of string, k: conn_id): interval {
  # print(fmt("Expiring %s sz=%s", k, |t|));
  return 0sec;
}

global recent_conns: table[conn_id] of string &create_expire=0.05sec &expire_func=expire;

event new_connection(c: connection) {
  # print(fmt("%s %s", c$id, network_time()));
  recent_conns[c$id] = c$uid;
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
