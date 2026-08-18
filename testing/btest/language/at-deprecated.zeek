# @TEST-EXEC: zeek -b foo
# @TEST-EXEC: btest-diff-remove-abspath .stderr

# @TEST-START-FILE foo.zeek
@deprecated
@load bar
@load baz
# @TEST-END-FILE

# @TEST-START-FILE bar.zeek
@deprecated "Use '@load qux' instead"
# @TEST-END-FILE

# @TEST-START-FILE baz.zeek
@deprecated
# @TEST-END-FILE
