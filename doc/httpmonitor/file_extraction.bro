
global mime_to_ext: table[string] of string = {
	["application/x-dosexec"] = "exe",
	["text/plain"] = "txt",
	["image/jpeg"] = "jpg",
	["image/png"] = "png",
	["text/html"] = "html",
};

event file_mime_type(f: fa_file, mime_type: string)
	{
	if ( f$source != "HTTP" )
		return;

	if ( mime_type !in mime_to_ext )
		return;

	local fname = fmt("%s-%s.%s", f$source, f$id, mime_to_ext[mime_type]);
	print fmt("Extracting file %s", fname);
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	}