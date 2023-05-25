# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: spicyz -d -o ssh.hlto ssh.spicy ./ssh.evt
# @TEST-EXEC: zeek -b Zeek::Spicy ssh.hlto %INPUT >>output
# @TEST-EXEC: echo >>output
# @TEST-EXEC: zeek -b Zeek::Spicy %INPUT >>output
# @TEST-EXEC: btest-diff output
#
# @TEST-DOC: Check that we can access ANALYZER_* tags during Zeek-side script parse time.

# @TEST-START-FILE ssh.spicy
module SSH;
public type Banner = unit {};
# @TEST-END-FILE

# @TEST-START-FILE ssh.evt
protocol analyzer spicy::SSH over TCP:
    parse with SSH::Banner;
# @TEST-END-FILE

@ifdef ( Analyzer::ANALYZER_SPICY_SSH )
event zeek_init()
    {
    print "Have analyzer!";
    print fmt("tag: %s", Analyzer::get_tag("spicy_SSH"));
    print fmt("name: %s", Analyzer::name(Analyzer::ANALYZER_SPICY_SSH));
    }
@else
event zeek_init()
    {
    print "Do not have analyzer!";
    }
@endif
