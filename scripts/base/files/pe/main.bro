module PE;

@load ./consts.bro

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Current timestamp.
		ts:                  time              &log;
		## File id of this portable executable file.
		id:                  string            &log;
		## The target machine that the file was compiled for.
		machine:             string            &log &optional;
		## The time that the file was created at.
		compile_ts:          time              &log &optional;
		## The required operating system.
		os:                  string            &log &optional;
		## The subsystem that is required to run this file.
		subsystem:           string            &log &optional;
		## Is the file an executable, or just an object file?
		is_exe:              bool              &log &default=T;
		## Is the file a 64-bit executable?
		is_64bit:            bool              &log &default=T;
		## Does the file support Address Space Layout Randomization?
		uses_aslr:           bool              &log &default=F;
		## Does the file support Data Execution Prevention?
		uses_dep:            bool              &log &default=F;
		## Does the file enforce code integrity checks?
		uses_code_integrity: bool              &log &default=F;
		## Does the file use structured exception handing?
		uses_seh:            bool              &log &default=T;
		## Does the file have an import table?
		has_import_table:    bool              &log &optional;
		## Does the file have an export table?
		has_export_table:    bool              &log &optional;
		## Does the file have an attribute certificate table?
		has_cert_table:      bool              &log &optional;
		## Does the file have a debug table?
		has_debug_data:      bool              &log &optional;
		## The names of the sections, in order.
		section_names:       vector of string  &log &optional;
	};

	## Event for accessing logged records.
	global log_pe: event(rec: Info);

	## A hook that gets called when we first see a PE file.
	global set_file: hook(f: fa_file);
}

redef record fa_file += {
	pe: Info &optional;
};

const pe_mime_types = { "application/x-dosexec" };

event bro_init() &priority=5
	{
	Files::register_for_mime_types(Files::ANALYZER_PE, pe_mime_types);
	Log::create_stream(LOG, [$columns=Info, $ev=log_pe, $path="pe"]);
	}

hook set_file(f: fa_file) &priority=5
	{
	if ( ! f?$pe )
		f$pe = [$ts=network_time(), $id=f$id];
	}

event pe_dos_header(f: fa_file, h: PE::DOSHeader) &priority=5
	{
	hook set_file(f);
	}

event pe_file_header(f: fa_file, h: PE::FileHeader) &priority=5
	{
	hook set_file(f);

	f$pe$machine    = machine_types[h$machine];
	f$pe$compile_ts = h$ts;
	f$pe$is_exe     = ( h$optional_header_size > 0 );

	for ( c in h$characteristics )
		{
		if ( file_characteristics[c] == "32BIT_MACHINE" )
			f$pe$is_64bit = F;
		}
	}

event pe_optional_header(f: fa_file, h: PE::OptionalHeader) &priority=5
	{
	hook set_file(f);

	# Only EXEs have optional headers
	if ( ! f$pe$is_exe )
		return;

	f$pe$os        = os_versions[h$os_version_major, h$os_version_minor];
	f$pe$subsystem = windows_subsystems[h$subsystem];

	for ( c in h$dll_characteristics )
		{
		if ( dll_characteristics[c] == "DYNAMIC_BASE" )
			f$pe$uses_aslr = T;
		if ( dll_characteristics[c] == "FORCE_INTEGRITY" )
			f$pe$uses_code_integrity = T;
		if ( dll_characteristics[c] == "NX_COMPAT" )
			f$pe$uses_dep = T;
		if ( dll_characteristics[c] == "NO_SEH" )
			f$pe$uses_seh = F;
		}

	f$pe$has_export_table = (|h$table_sizes| > 0 && h$table_sizes[0] > 0);
	f$pe$has_import_table = (|h$table_sizes| > 1 && h$table_sizes[1] > 0);
	f$pe$has_cert_table   = (|h$table_sizes| > 4 && h$table_sizes[4] > 0);
	f$pe$has_debug_data   = (|h$table_sizes| > 6 && h$table_sizes[6] > 0);
	}

event pe_section_header(f: fa_file, h: PE::SectionHeader) &priority=5
	{
	hook set_file(f);

	# Only EXEs have section headers
	if ( ! f$pe$is_exe )
		return;

	if ( ! f$pe?$section_names )
		f$pe$section_names = vector();
	f$pe$section_names[|f$pe$section_names|] = h$name;
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f?$pe && f$pe?$machine )
		Log::write(LOG, f$pe);
	}

