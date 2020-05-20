# @TEST-EXEC: zeek -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT >get.out
# @TEST-EXEC: btest-diff get.out
# @TEST-EXEC: test ! -s Cx92a0ym5R8-file

event file_new(f: fa_file)
	{
	Files::stop(f);
	}
