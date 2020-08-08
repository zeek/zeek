# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace $SCRIPTS/file-analysis-test.zeek %INPUT >get.out
# @TEST-EXEC: btest-diff get.out
# @TEST-EXEC: test ! -s Cx92a0ym5R8-file

@load base/protocols/http

event file_new(f: fa_file)
	{
	Files::stop(f);
	}
