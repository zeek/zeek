# @TEST-EXEC: zeek -b %INPUT
# @TEST-DOC:  Regression test #2017; no output check, just shouldn't crash

redef table_expire_interval = 0.1sec;
redef table_incremental_step = 100;
redef table_expire_delay = 0.5sec;

redef exit_only_after_terminate = T;

global tbl: table[string] of vector of count &default = vector() &create_expire=1sec;

const populates_per_second = 100;
const populates_num = 100;
global done = F;

event do_terminate() {
  terminate();
}

event cleanup(idx: string) {
  delete tbl[idx];

  # terminate a bit after all elements will finally have been expired
  if ( done && |tbl| == 0 )
    schedule 1sec { do_terminate() };
}

event populate(round: count) {

  local i = 0;
  while (++i < populates_num) {
    local val = rand(1000000);
    local val_str = cat(val);
    # print(fmt("round %s %s val=%s", round, i, val));
    tbl[val_str] = vector(val);

    # Schedule an explicit delete at most a second away.
    local random_cleanup_delay = double_to_interval(rand(100) / 100.0);
    schedule random_cleanup_delay { cleanup(val_str) };
  }

  if ( round <= 200 ) {
    print(fmt("round %s size=%s", round, |tbl|));
    schedule 1sec/populates_per_second { populate(++round) };
  }
  else
    done = T;
}

event zeek_init() {
  event populate(1);
}
