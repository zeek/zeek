# @TEST-DOC: Test file-hash event with the different hashing algorithms.#

# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-sort btest-diff .stdout

@load base/protocols/http

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	Files::add_analyzer(f, Files::ANALYZER_SHA224);
	Files::add_analyzer(f, Files::ANALYZER_SHA256);
	Files::add_analyzer(f, Files::ANALYZER_SHA384);
	Files::add_analyzer(f, Files::ANALYZER_SHA512);
	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	print kind, hash;
	}
