# @TEST-EXEC: zeek -b -r $TRACES/http/content-range-gap.trace %INPUT
# @TEST-EXEC: btest-diff --binary extract_files/thefile

@load base/protocols/http
@load base/files/extract

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
					   [$extract_filename="thefile"]);
	}
