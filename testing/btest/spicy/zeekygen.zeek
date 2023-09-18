# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -D zeek -o test.hlto doc.spicy ./doc.evt >output 2>&1
# @TEST-EXEC: cat output | grep 'module.s documentation' >output1
# @TEST-EXEC: btest-diff output1
#
# @TEST-DOC: Check that Spicy's tells Zeeygen about its analyzers. (TODO: Test only partially implemented right now)

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
