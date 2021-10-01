# @TEST-EXEC: zeek %INPUT > output
# @TEST-EXEC: btest-diff output

# Validate that we can pass the individual Tag types into functions that
# take both their own Tag type as well the AllAnalyzers type.

global test2: function(a: Analyzer::Tag);
global test3: function(a: PacketAnalyzer::Tag);
global test4: function(a: Files::Tag);

function test1(a: AllAnalyzers::Tag) {
    print "all", a;
}

function test2(a: Analyzer::Tag) {
    print "analyzer", a;
}

function test3(a: PacketAnalyzer::Tag) {
    print "packet analyzer", a;
}

function test4(a: Files::Tag) {
    print "file analyzer", a;
}

event zeek_init() {
    test1(Analyzer::ANALYZER_DNS);
    test2(Analyzer::ANALYZER_DNS);

    test1(PacketAnalyzer::ANALYZER_UDP);
    test3(PacketAnalyzer::ANALYZER_UDP);

    test1(Files::ANALYZER_X509);
    test4(Files::ANALYZER_X509);
}