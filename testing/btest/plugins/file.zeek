# @TEST-EXEC: ${DIST}/auxil/zeek-aux/plugin-support/init-plugin -u . Demo Foo
# @TEST-EXEC: cp -r %DIR/file-plugin/* .
# @TEST-EXEC: ./configure --zeek-dist=${DIST} && make
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -NN Demo::Foo >>output
# @TEST-EXEC: echo === >>output
# @TEST-EXEC: ZEEK_PLUGIN_PATH=`pwd` zeek -r $TRACES/ftp/retr.trace %INPUT >>output
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff output
# @TEST-EXEC: btest-diff weird.log

# Suppress AnalyzerViolation() after the third one and create a weird.log.
redef max_analyzer_violations = 3;

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_FOO);
	}

event foo_piece(f: fa_file, data: string)
	{
	print "foo_piece", f$id, sub_bytes(data, 0, 20);
	}

event analyzer_confirmation_info(tag: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo)
	{
	print "analyzer_confirmation_info", tag, info$f$id;
	}

event analyzer_violation_info(tag: AllAnalyzers::Tag, info: AnalyzerViolationInfo)
	{
	print "analyzer_violation_info", tag, info$f$id, info$reason, info$data;
	}
