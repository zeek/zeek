# @TEST-EXEC: bro -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.bro %INPUT >get.out
# @TEST-EXEC: btest-diff get.out
# @TEST-EXEC: test ! -s Cx92a0ym5R8-file

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, f: fa_file)
	{
	if ( trig != FileAnalysis::TRIGGER_NEW ) return;
	FileAnalysis::stop(f);
	}
