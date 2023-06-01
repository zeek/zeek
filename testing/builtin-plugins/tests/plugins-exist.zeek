# @TEST-DOC: Assumes the plugins within Files/ have been builtin

# @TEST-EXEC: zeek -N Zeek::PyLib >>out
# @TEST-EXEC: zeek -N Demo::Foo >>out
# @TEST-EXEC: zeek -N Demo::Version >>out
# @TEST-EXEC: btest-diff out
