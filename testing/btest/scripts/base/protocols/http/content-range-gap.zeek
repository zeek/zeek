# @TEST-EXEC: zeek -r $TRACES/http/content-range-gap.trace %INPUT
# @TEST-EXEC: btest-diff extract_files/thefile

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
					   [$extract_filename="thefile"]);
	}
