# @TEST-EXEC: zeek -C -b -r $TRACES/pe/pe.trace %INPUT >out
# @TEST-EXEC: zeek -C -b -r $TRACES/pe/pe.trace %INPUT disable_it=T >>out
# @TEST-EXEC: btest-diff out

@load base/protocols/ftp

option disable_it = F;

event zeek_init()
	{
	local pe_mime_types: set[string] = { "application/x-dosexec" };
	Files::register_for_mime_types(Files::ANALYZER_PE, pe_mime_types);

	print Files::analyzer_enabled(Files::ANALYZER_PE);

	Files::enable_analyzer(Files::ANALYZER_PE);
	print Files::analyzer_enabled(Files::ANALYZER_PE);

	if ( disable_it )
		{
		Files::disable_analyzer(Files::ANALYZER_PE);
		print Files::analyzer_enabled(Files::ANALYZER_PE);
		}
	}

event pe_dos_header(f: fa_file, h: PE::DOSHeader)
	{
	print "got pe_dos_header event";
	exit(0);
	}
