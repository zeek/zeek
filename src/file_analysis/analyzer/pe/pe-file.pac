%include pe-file-types.pac
%include pe-file-headers.pac

# The base record for a Portable Executable file
type PE_File = case $context.connection.is_done() of {
	false -> PE      : Portable_Executable;
	true  -> overlay : bytestring &length=1 &transient;
};

type Portable_Executable = record {
	headers : Headers;
	pad     : Padding(restofdata);
} &let {
	unparsed_hdr_len: uint32 = headers.pe_header.size_of_headers - headers.length;
	restofdata: uint64 = headers.pe_header.is_exe ? $context.connection.get_max_file_location() - headers.pe_header.size_of_headers + unparsed_hdr_len : 0;
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
