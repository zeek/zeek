# @TEST-REQUIRES: have-spicy
#
# @TEST-DOC: Exercise end-of-data behavior for combinations of units expected certain amounts and regular vs non-regular connection termination.
#
# @TEST-EXEC: spicyz -d -o foo-16.hlto test.spicy foo-16.evt
# @TEST-EXEC: spicyz -d -o foo-136.hlto test.spicy foo-136.evt
# @TEST-EXEC: spicyz -d -o foo-1024.hlto test.spicy foo-1024.evt
# @TEST-EXEC: spicyz -d -o foo-eod.hlto test.spicy foo-eod.evt

# @TEST-EXEC: echo "=== Too much data, regular FINs (expect event output)" >>output-16-fins
# @TEST-EXEC: rm -f analyzer_debug.log && zeek -b -r ${TRACES}/http/get.trace Zeek::Spicy foo-16.hlto %INPUT >>output-16-fins
# @TEST-EXEC: test '!' -f analyzer_debug.log
# @TEST-EXEC: btest-diff output-16-fins

# @TEST-EXEC: echo "=== Too much data, missing FINs (expect event output)" >>output-16-no-fins
# @TEST-EXEC: rm -f analyzer_debug.log && zeek -b -r ${TRACES}/http/get-without-fins.trace Zeek::Spicy foo-16.hlto %INPUT >>output-16-no-fins
# @TEST-EXEC: test '!' -f analyzer_debug.log
# @TEST-EXEC: btest-diff output-16-no-fins

# @TEST-EXEC: echo "=== Exact data, regular FINs (expect event output)" >>output-136-fins
# @TEST-EXEC: rm -f analyzer_debug.log && zeek -b -r ${TRACES}/http/get.trace Zeek::Spicy foo-136.hlto %INPUT >>output-136-fins
# @TEST-EXEC: test '!' -f analyzer_debug.log
# @TEST-EXEC: btest-diff output-136-fins

# @TEST-EXEC: echo "=== Exact data, missing FINs (expect event output)" >>output-136-no-fins
# @TEST-EXEC: rm -f analyzer_debug.log && zeek -b -r ${TRACES}/http/get-without-fins.trace Zeek::Spicy foo-136.hlto %INPUT >>output-136-no-fins
# @TEST-EXEC: test '!' -f analyzer_debug.log
# @TEST-EXEC: btest-diff output-136-no-fins

# @TEST-EXEC: echo "=== Not enough data, regular FINs (expect analyzer error)" >>output-1024-fins
# @TEST-EXEC: rm -f analyzer_debug.log && zeek -b -r ${TRACES}/http/get.trace Zeek::Spicy foo-1024.hlto %INPUT >>output-1024-fins
# @TEST-EXEC: test -f analyzer_debug.log && zeek-cut failure_reason <analyzer_debug.log | diff-remove-abspath >>output-1024-fins
# @TEST-EXEC: btest-diff output-1024-fins

# @TEST-EXEC: echo "=== Not enough data, missing FINs (expect no output)" >>output-1024-no-fins
# @TEST-EXEC: rm -f analyzer_debug.log && zeek -b -r ${TRACES}/http/get-without-fins.trace Zeek::Spicy foo-1024.hlto %INPUT >>output-1024-no-fins
# @TEST-EXEC: test '!' -f analyzer_debug.log
# @TEST-EXEC: btest-diff output-1024-no-fins

# @TEST-EXEC: echo "=== Until EOD, regular FINs (expect event output)" >>output-eod-fins
# @TEST-EXEC: rm -f analyzer_debug.log && zeek -b -r ${TRACES}/http/get.trace Zeek::Spicy foo-eod.hlto %INPUT >>output-eod-fins
# @TEST-EXEC: test '!' -f analyzer_debug.log
# @TEST-EXEC: btest-diff output-eod-fins

# @TEST-EXEC: echo "=== Until EOD, missing FINs (expect no output)" >>output-eod-no-fins
# @TEST-EXEC: rm -f analyzer_debug.log && zeek -b -r ${TRACES}/http/get-without-fins.trace Zeek::Spicy foo-eod.hlto %INPUT >>output-eod-no-fins
# @TEST-EXEC: test '!' -f analyzer_debug.log
# @TEST-EXEC: btest-diff output-eod-no-fins

@load frameworks/analyzer/analyzer-debug-log.zeek
redef Analyzer::DebugLogging::include_confirmations = F;
redef Analyzer::DebugLogging::include_disabling = F;

event Test::foo() {
    print "event foo()";
    }

# @TEST-START-FILE test.spicy
module Test;

public type Foo16 = unit {
    : bytes &size=16;
};

public type Foo136 = unit {
    : bytes &size=136;
};

public type Foo1024 = unit {
    : bytes &size=1024;
};

public type FooEOD = unit {
    : bytes &eod;
};

# @TEST-END-FILE

# @TEST-START-FILE foo-16.evt

protocol analyzer spicy::Foo over TCP:
    parse originator with Test::Foo16,
    port 80/tcp;

on Test::Foo16 -> event Test::foo();
# @TEST-END-FILE

# @TEST-START-FILE foo-136.evt
protocol analyzer spicy::Foo over TCP:
    parse originator with Test::Foo136,
    port 80/tcp;

on Test::Foo136 -> event Test::foo();
# @TEST-END-FILE

# @TEST-START-FILE foo-1024.evt
protocol analyzer spicy::Foo over TCP:
    parse originator with Test::Foo1024,
    port 80/tcp;

on Test::Foo1024 -> event Test::foo();
# @TEST-END-FILE

# @TEST-START-FILE foo-eod.evt
protocol analyzer spicy::Foo over TCP:
    parse originator with Test::FooEOD,
    port 80/tcp;

on Test::FooEOD -> event Test::foo();
# @TEST-END-FILE

