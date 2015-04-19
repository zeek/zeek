
module PE;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:                  time              &log;
		fuid:                string            &log;
		machine:             string            &log &optional;
		compile_ts:          time              &log &optional;
		os:                  string            &log &optional;
		subsystem:           string            &log &optional;

	 	is_exe:              bool              &log &default=F;
		is_dll:              bool              &log &default=F;
	        is_64bit:            bool              &log &default=T;

		uses_aslr:           bool              &log &default=F;
	        uses_dep:            bool              &log &default=F;
	        uses_code_integrity: bool              &log &default=F;
	        uses_seh:            bool              &log &default=T;
	        
		has_import_table:    bool              &log &optional;
	        has_export_table:    bool              &log &optional;
	        has_cert_table:      bool              &log &optional;
	        has_debug_data:      bool              &log &optional;
		
		section_names:       vector of string  &log &optional;
	};

	global set_file: hook(f: fa_file);
}

redef record Info += {
	confirmed: bool &default=F;
};

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
		f$pe = [$ts=network_time(), $fuid=f$id];
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
		{
		if ( c == 0x2 )
			f$pe$is_exe = T;
		if ( c == 0x100 )
			f$pe$is_64bit = F;
		if ( c == 0x2000 )
			f$pe$is_dll = T;
		}
	}

event pe_optional_header(f: fa_file, h: PE::OptionalHeader) &priority=5
	{
	hook set_file(f);

	if ( h$magic == 0x10b || h$magic == 0x20b )
		f$pe$confirmed = T;
	else
		return;
		
	f$pe$os = os_versions[h$os_version_major, h$os_version_minor];
	f$pe$subsystem = windows_subsystems[h$subsystem];
	for ( c in h$dll_characteristics )
		{
		if ( c == 0x40 )
			f$pe$uses_aslr = T;
		if ( c == 0x80 )
			f$pe$uses_code_integrity = T;
		if ( c == 0x100 )
			f$pe$uses_dep = T;
		if ( c == 0x400 )
			f$pe$uses_seh = F;
		}
	}

event pe_section_header(f: fa_file, h: PE::SectionHeader) &priority=5
	{
	hook set_file(f);

	if ( ! f$pe?$section_names )
		f$pe$section_names = vector();
	f$pe$section_names[|f$pe$section_names|] = h$name;
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f?$pe && f$pe$confirmed )
		Log::write(LOG, f$pe);
	}

event file_mime_type(f: fa_file, mime_type: string)
	{
	if ( mime_type == /application\/x-dosexec.*/ ) 
		{
		Files::add_analyzer(f, Files::ANALYZER_PE);
		}
	}
