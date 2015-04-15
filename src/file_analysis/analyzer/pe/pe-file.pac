%include pe-file-types.pac
%include pe-file-headers.pac
%include pe-file-idata.pac

# The base record for a Portable Executable file
type PE_File = record {
	headers         : Headers;
	pad		: Padding(iat_loc);
	iat		: idata &length=$context.connection.get_import_table_len();
} &let {
	unparsed_hdr_len: uint32 = headers.pe_header.optional_header.size_of_headers - headers.length;
	iat_loc: uint32 = $context.connection.get_import_table_addr() - headers.pe_header.optional_header.size_of_headers + unparsed_hdr_len;
} &byteorder=littleendian;

