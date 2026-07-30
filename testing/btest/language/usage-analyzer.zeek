# @TEST-DOC: Simple testing for unused function/event detection to ensure nothing breaks when modifying it.
# @TEST-EXEC: zeek -b %INPUT
# @TEST-EXEC: btest-diff-remove-abspath .stderr

module MyModule;

function gen_id(): string { return cat(rand(10000)); }
function gen_id2(): string { return gen_id2(); }

function helper() { }
event MyModule::unused(c: count) { helper(); }
