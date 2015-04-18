%include pe-file-types.pac
%include pe-file-headers.pac
%include pe-file-idata.pac

# The base record for a Portable Executable file
type PE_File = case $context.connection.is_done() of {
	false -> PE      : Portable_Executable;
	true  -> overlay : bytestring &length=1 &transient;
};

type Portable_Executable = record {
	headers : Headers;
	pad1	: Padding(iat_loc);
	iat     : idata &length=$context.connection.get_import_table_len();
	pad2    : Padding(restofdata);
} &let {
	unparsed_hdr_len: uint32 = headers.pe_header.optional_header.size_of_headers - headers.length;
	iat_loc: uint64 = $context.connection.get_import_table_addr() - headers.pe_header.optional_header.size_of_headers + unparsed_hdr_len;
	restofdata: uint64 = $context.connection.get_max_file_location() - $context.connection.get_import_table_addr() - $context.connection.get_import_table_len();
	proc: bool = $context.connection.proc_pe(this);
} &byteorder=littleendian;

refine connection MockConnection += {

	%member{
		bool done_;
	%}

	%init{
		done_ = false;
	%}

	function proc_pe(p: Portable_Executable): bool
		%{
		done_ = true;
		return true;
		%}

	function is_done(): bool
		%{
		return done_;
		%}
};
