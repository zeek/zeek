# This testcase used to cause subtle memory overflow problems due to deviating
# traversal order of the k$a set members. With 4.2, this will trigger an
# InternalError due to new bounds-checking. For context, see GHI-1753.
#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

type Key: record {
  a: set[string];
  b: string &optional;
  c: string &optional;
};

global state: table[Key] of count = {};

event zeek_init() {

  local k: Key;

  k$a = set("MD5", "SHA1");
  k$b = "12345678901234567890";

  state[k] = 1;
  print k;
}
