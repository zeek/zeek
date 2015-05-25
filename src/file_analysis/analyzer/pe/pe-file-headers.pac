type Headers = record {
	dos_header      : DOS_Header;
	dos_code        : DOS_Code(dos_code_len);
	pe_header       : NT_Headers;
	section_headers : Section_Headers(pe_header.file_header.NumberOfSections);
} &let {
	dos_code_len: uint32 = dos_header.AddressOfNewExeHeader > 64 ? dos_header.AddressOfNewExeHeader - 64 : 0;
	length: uint64 = 64 + dos_code_len + pe_header.length + section_headers.length;
};

# The DOS header gives us the offset of the NT headers
type DOS_Header = record {
	signature                : bytestring &length=2;
	UsedBytesInTheLastPage   : uint16;
	FileSizeInPages          : uint16;
	NumberOfRelocationItems  : uint16;
	HeaderSizeInParagraphs   : uint16;
	MinimumExtraParagraphs   : uint16;
	MaximumExtraParagraphs   : uint16;
	InitialRelativeSS        : uint16;
	InitialSP                : uint16;
	Checksum                 : uint16;
	InitialIP                : uint16;
	InitialRelativeCS        : uint16;
	AddressOfRelocationTable : uint16;
	OverlayNumber            : uint16;
	Reserved                 : uint16[4];
	OEMid                    : uint16;
	OEMinfo                  : uint16;
	Reserved2                : uint16[10];
	AddressOfNewExeHeader    : uint32;
} &length=64;

type DOS_Code(len: uint32) = record {
	code : bytestring &length=len;
};

# The NT headers give us the file and the optional headers.
type NT_Headers = record {
	PESignature     : uint32;
	file_header     : File_Header;
	have_opt_header : case is_exe of {
		true  -> optional_header : Optional_Header &length=file_header.SizeOfOptionalHeader;
		false -> none: empty;
		};
} &let {
	length: uint32 = file_header.SizeOfOptionalHeader + offsetof(have_opt_header);
	is_exe: bool = file_header.SizeOfOptionalHeader > 0;
	size_of_headers: uint32 = is_exe ? optional_header.size_of_headers : 0;
} &length=length;

# The file header is mainly self-describing
type File_Header = record {
	Machine               : uint16;
	NumberOfSections      : uint16;
	TimeDateStamp         : uint32;
	PointerToSymbolTable  : uint32;
	NumberOfSymbols       : uint32;
	SizeOfOptionalHeader  : uint16;
	Characteristics       : uint16;
};

# The optional header gives us DLL link information, and some structural information
type Optional_Header = record {
	magic                   : uint16;
	major_linker_version    : uint8;
	minor_linker_version    : uint8;
	size_of_code            : uint32;
	size_of_init_data       : uint32;
	size_of_uninit_data     : uint32;
	addr_of_entry_point     : uint32;
	base_of_code            : uint32;
	have_base_of_data: case pe_format of {
		PE32    -> base_of_data: uint32;
		default -> not_present:  empty;
	} &requires(pe_format);
	is_pe32: case pe_format of {
		PE32_PLUS -> image_base_64: uint64;
		default   -> image_base_32: uint32;
	} &requires(pe_format);
	section_alignment       : uint32;
	file_alignment          : uint32;
	os_version_major        : uint16;
	os_version_minor        : uint16;
	major_image_version     : uint16;
	minor_image_version     : uint16;
	major_subsys_version    : uint16;
	minor_subsys_version    : uint16;
	win32_version           : uint32;
	size_of_image           : uint32;
	size_of_headers         : uint32;
	checksum                : uint32;
	subsystem               : uint16;
	dll_characteristics     : uint16;
	mem: case pe_format of {
		PE32      -> i32: Mem_Info32;
		PE32_PLUS -> i64: Mem_Info64;
		default -> InvalidPEFile : empty;
	} &requires(pe_format);
	loader_flags            : uint32;
	number_of_rva_and_sizes : uint32;
	rvas			: RVAS(number_of_rva_and_sizes);
} &let {
	pe_format : uint8 = $context.connection.set_pe32_format(magic);
	image_base: uint64 = pe_format == PE32_PLUS ? image_base_64 : image_base_32;
};

type Section_Headers(num: uint16) = record {
	sections : Section_Header[num];
} &let {
	length: uint32 = num*40;
} &length=length;

type Section_Header = record {
	name                      : bytestring &length=8;
	virtual_size              : uint32;
	virtual_addr              : uint32;
	size_of_raw_data          : uint32;
	ptr_to_raw_data           : uint32;
	non_used_ptr_to_relocs    : uint32;
	non_used_ptr_to_line_nums : uint32;
	non_used_num_of_relocs    : uint16;
	non_used_num_of_line_nums : uint16;
	characteristics           : uint32;
} &let {
	add_section: bool = $context.connection.add_section(this);
} &length=40;

refine connection MockConnection += {
	%member{
		uint64 max_file_location_;
		uint8  pe32_format_;
	%}

	%init{
		max_file_location_ = 0;
		pe32_format_ = UNKNOWN_VERSION;;
	%}

	function add_section(h: Section_Header): bool
		%{
		if ( ${h.size_of_raw_data} + ${h.ptr_to_raw_data} > max_file_location_ )
			max_file_location_ = ${h.size_of_raw_data} + ${h.ptr_to_raw_data};

		return true;
		%}

	function set_pe32_format(magic: uint16): uint8
		%{
		if ( ${magic} == 0x10b )
			pe32_format_ = PE32;

		if ( ${magic} == 0x20b )
			pe32_format_ = PE32_PLUS;

		return pe32_format_;
		%}

	function get_max_file_location(): uint64
		%{
		return max_file_location_;
		%}

	function get_pe32_format(): uint8
		%{
		return pe32_format_;
		%}
};
