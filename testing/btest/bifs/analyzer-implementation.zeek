#
# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
{
    print Analyzer::implementation(Analyzer::ANALYZER_HTTP);
    print Analyzer::implementation(Analyzer::ANALYZER_LDAP_TCP);
}
