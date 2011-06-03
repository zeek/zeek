# @TEST-EXEC: bro %INPUT  >output 2>&1
# @TEST-EXEC: btest-diff output

# This is a test script whose job is to generate rarely-seen events
# (i.e., events that test traces might not include) to ensure that they're
# handled properly.

# This is needed or else the output fails on the warning that
# Drop::restore_dropped_address is never defined.
redef check_for_unused_event_handlers = F;

@load netstats

function test_net_stats_update()
    {
    local t = current_time();

    local s: net_stats;
    s$pkts_recvd = 1234;
    s$pkts_dropped = 123;
    s$pkts_link = 9999;

    event net_stats_update(t, s);

    local s2: net_stats;
    s2$pkts_recvd = 2341;
    s2$pkts_dropped = 125;
    s2$pkts_link = 19999;

    event net_stats_update(t + 33 sec, s2);
    }

event bro_init()
    {
    test_net_stats_update();
    }

