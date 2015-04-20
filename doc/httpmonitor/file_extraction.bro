
global mime_to_ext: table[string] of string = {
	["application/x-dosexec"] = "exe",
	["text/plain"] = "txt",
	["image/jpeg"] = "jpg",
	["image/png"] = "png",
	["text/html"] = "html",
};

event file_metadata_inferred(f: fa_file, meta: inferred_file_metadata)
	{
	if ( f$source != "HTTP" )
		return;

	if ( ! meta?$mime_type )
		return;

	if ( meta$mime_type !in mime_to_ext )
		return;

	local fname = fmt("%s-%s.%s", f$source, f$id, mime_to_ext[meta$mime_type]);
	print fmt("Extracting file %s", fname);
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	}
