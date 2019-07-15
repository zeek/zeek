# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

# At the moment, it's legal to allow a double definitions.  Internally, the
# reason/comment is: "so that we can define an enum both in a *.bif and *.zeek
# for avoiding cyclic dependencies."

type myenum: enum { ONE = 0x01 };
type myenum: enum { ONE = 0x01 };
print ONE;
