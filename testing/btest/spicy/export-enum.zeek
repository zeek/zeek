# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o x.hlto tupleenum.spicy ./tupleenum.evt
# @TEST-EXEC: zeek -r ${TRACES}/ssh/single-conn.trace x.hlto %INPUT >>output
# @TEST-EXEC: zeek -NN x.hlto | grep TestEnum >>output
#
# @TEST-EXEC: btest-diff output

event zeek_init() {
  local i: TupleEnum::TestEnum;

  i = TupleEnum::TestEnum_A;
  print i;

  i = TupleEnum::TestEnum_Undef;
  print i;
}

# @TEST-START-FILE tupleenum.evt

# @TEST-END-FILE

# @TEST-START-FILE tupleenum.spicy

module TupleEnum;

public type TestEnum = enum {
    A = 83, B = 84, C = 85
};

# @TEST-END-FILE
