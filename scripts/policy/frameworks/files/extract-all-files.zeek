##! Extract all files to disk.

@load base/files/extract

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
	}
