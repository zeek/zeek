# @TEST-IGNORE
#
# This file contains code used by the file analysis path-prefix tests.

redef exit_only_after_terminate = T;

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_MD5);
	}

event file_hash(f: fa_file, kind: string, hash: string)
	{
	print "file_hash", kind, hash;
	terminate();
	}
