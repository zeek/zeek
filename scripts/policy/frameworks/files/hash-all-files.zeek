##! Perform MD5 and SHA1 hashing on all files.

@load base/files/hash

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	}
