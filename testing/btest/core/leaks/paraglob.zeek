# Needs perftools support.
#
# @TEST-GROUP: leaks
#
# @TEST-REQUIRES: zeek  --help 2>&1 | grep -q mem-leaks
#
# @TEST-EXEC: HEAP_CHECK_DUMP_DIRECTORY=. HEAPCHECK=local btest-bg-run zeek zeek -m -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-bg-wait 120

event new_connection (c : connection)
{
  local v1 = vector("*", "d?g", "*og", "d?", "d[!wl]g");
  local v2 = vector("once", "!o*", "once");
  local v3 = vector("https://*.google.com/*", "*malware*", "*.gov*");

  local p1 = paraglob_init(v1);
  local p2: opaque of paraglob = paraglob_init(v2);
  local p3 = paraglob_init(v3);
  local p_eq = paraglob_init(v1);

  # paraglob_init should not modify v1
  print (v1 == vector("*", "d?g", "*og", "d?", "d[!wl]g"));
  # p_eq and p1 should be the same paraglobs
  print paraglob_equals(p_eq, p1);

  print paraglob_get(p1, "dog");


  print paraglob_get(p2, "once");
  print paraglob_get(p3, "www.strange-malware-domain.gov");

  local large_glob: opaque of paraglob = paraglob_init(v3);
  print paraglob_get(large_glob, "www.strange-malware-domain.gov");
}
