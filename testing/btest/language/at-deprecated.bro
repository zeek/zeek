# @TEST-EXEC: bro -b foo
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

@TEST-START-FILE foo.bro
@deprecated
@load bar
@load baz
@TEST-END-FILE

@TEST-START-FILE bar.bro
@deprecated "Use '@load qux.bro' instead"
@TEST-END-FILE

@TEST-START-FILE baz.bro
@deprecated
@TEST-END-FILE
