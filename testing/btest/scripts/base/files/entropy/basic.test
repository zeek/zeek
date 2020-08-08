# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: btest-diff .stdout

@load base/protocols/http

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_ENTROPY);
	}

event file_entropy(f: fa_file, ent: entropy_test_result)
	{
	print ent;
	}
