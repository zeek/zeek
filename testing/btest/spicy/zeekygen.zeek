# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -D zeek -o test.hlto doc.spicy ./doc.evt >output 2>&1
# @TEST-EXEC: cat output | grep 'module.s documentation' >output1
# @TEST-EXEC: btest-diff output1
#
# @TEST-EXEC: unset ZEEK_DISABLE_ZEEKYGEN && zeek -X zeekygen.conf test.hlto %INPUT
# @TEST-EXEC: cat protocol.rst  | sed -n '/_plugin-foo-bar/,/_plugin/p' | sed '$d' >output2
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output2
#
# @TEST-DOC: Check that Spicy tells Zeekygen about its analyzers.

## Test event.
##
## Really, just a test ...

global ssh::banner: event(c: connection, facility: count, severity: count, msg: string);

# @TEST-START-FILE doc.spicy

module SSH;

import zeek;

public type Banner = unit {
    magic   : /SSH-/;
    version : /[^-]*/;
    dash    : /-/;
    software: /[^\r\n]*/;
};
# @TEST-END-FILE

# @TEST-START-FILE doc.evt

%doc-id = Foo::Bar;
%doc-description = "Just a \"test\" analyzer.h";

protocol analyzer spicy::SSH over TCP:
    parse originator with SSH::Banner,
    port 22/tcp,
    replaces SSH;

on SSH::Banner -> event ssh::banner((1, self.software));

# @TEST-END-FILE

# @TEST-START-FILE zeekygen.conf
proto_analyzer	*	protocol.rst

