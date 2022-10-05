# @TEST-DOC: Add the PE analyzer to Analyzer::disabled_analyzers and ensure no pe.log is created.

# First, cross-check that pe.log is indeed generated.
# @TEST-EXEC: zeek -b -r $TRACES/pe/pe.trace %INPUT
# @TEST-EXEC: test -f pe.log
# @TEST-EXEC: rm *log

# @TEST-EXEC: zeek -b -r $TRACES/pe/pe.trace %INPUT 'Analyzer::disabled_analyzers += { Files::ANALYZER_PE }'
# @TEST-EXEC: test ! -f pe.log
# @TEST-EXEC: test -f conn.log
# @TEST-EXEC: rm *log

# Finally, explicitly enable the analyzer via Analyzer::enable_analyzer() during zeek_init() and expect pe.log to be generated.
# @TEST-EXEC: zeek -b -r $TRACES/pe/pe.trace %INPUT 'Analyzer::disabled_analyzers += { Files::ANALYZER_PE }' -e 'event zeek_init() { Analyzer::enable_analyzer(Files::ANALYZER_PE); }'
# @TEST-EXEC: test -f pe.log
# @TEST-EXEC: test -f conn.log

@load base/protocols/conn
@load base/protocols/ftp
@load base/files/pe
