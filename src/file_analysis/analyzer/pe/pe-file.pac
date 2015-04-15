%include pe-file-types.pac
%include pe-file-headers.pac
%include pe-file-idata.pac

# The base record for a Portable Executable file
type PE_File = record {
	headers : Headers;
	pad1	: Padding(iat_loc);
	iat     : idata &length=$context.connection.get_import_table_len();
	pad2    : Padding(restofdata);
} &let {
	unparsed_hdr_len: uint32 = headers.pe_header.optional_header.size_of_headers - headers.length;
	iat_loc: uint64 = $context.connection.get_import_table_addr() - headers.pe_header.optional_header.size_of_headers + unparsed_hdr_len;
	restofdata: uint64 = $context.connection.get_max_file_location() - $context.connection.get_import_table_addr() - $context.connection.get_import_table_len();
} &byteorder=littleendian;

