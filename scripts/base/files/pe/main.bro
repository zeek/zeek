
module PE;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:              time             &log;
		fuid:            string           &log;
		machine:         string           &log &optional;
		compile_ts:      time             &log &optional;
		os:              string           &log &optional;
		subsystem:       string           &log &optional;
		characteristics: set[string]      &log &optional;
		section_names:   vector of string &log &optional;
	};


	global set_file: hook(f: fa_file);
}

redef record fa_file += {
	pe: Info &optional;
};

event bro_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info]);
	}

hook set_file(f: fa_file) &priority=5
	{
	if ( ! f?$pe )
		{
		local c: set[string] = set();
		f$pe = [$ts=network_time(), $fuid=f$id, $characteristics=c];
		}
	}

event pe_dos_header(f: fa_file, h: PE::DOSHeader) &priority=5
	{
	hook set_file(f);
	}

event pe_file_header(f: fa_file, h: PE::FileHeader) &priority=5
	{
	hook set_file(f);
	f$pe$compile_ts = h$ts;
	f$pe$machine    = machine_types[h$machine];
	for ( c in h$characteristics )
		add f$pe$characteristics[PE::file_characteristics[c]];
	}

event pe_optional_header(f: fa_file, h: PE::OptionalHeader) &priority=5
	{
	hook set_file(f);
	f$pe$os = os_versions[h$os_version_major, h$os_version_minor];
	f$pe$subsystem = windows_subsystems[h$subsystem];
	}

event pe_section_header(f: fa_file, h: PE::SectionHeader) &priority=5
	{
	hook set_file(f);

	print h;
	if ( ! f$pe?$section_names )
		f$pe$section_names = vector();
	f$pe$section_names[|f$pe$section_names|] = h$name;
	}

event file_state_remove(f: fa_file)
	{
	if ( f?$pe )
		Log::write(LOG, f$pe);
	}

event file_new(f: fa_file)
	{
	if ( f?$mime_type && f$mime_type == /application\/x-dosexec.*/ ) 
		{
		#print "found a windows executable";
		Files::add_analyzer(f, Files::ANALYZER_PE);
		#FileAnalysis::add_analyzer(f, [$tag=FileAnalysis::ANALYZER_EXTRACT, 
		#                               $extract_filename=fmt("exe-%d", ++blah_counter)]);
		}
	}
