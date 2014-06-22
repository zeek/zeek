
type TheFile = record {
	dos_header      : DOS_Header;
	dos_code        : DOS_Code(dos_code_len);
	pe_header       : IMAGE_NT_HEADERS;
	section_headers : IMAGE_SECTIONS(pe_header.file_header.NumberOfSections);
	#pad             : bytestring &length=offsetof(pe_header.data_directories + pe_header.data_directories[1].virtual_address);
	#data_sections   : DATA_SECTIONS[pe_header.file_header.NumberOfSections];
	#data_sections   : DATA_SECTIONS[] &length=data_len;
} &let {
	dos_code_len: uint32 = dos_header.AddressOfNewExeHeader - 64;
	data_len: uint32 = pe_header.optional_header.size_of_init_data;
} &byteorder=littleendian;

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
} &byteorder=littleendian &length=64;

type DOS_Code(len: uint32) = record {
	code : bytestring &length=len;
};

type IMAGE_NT_HEADERS = record {
	PESignature     : uint32;
	file_header     : IMAGE_FILE_HEADER;
	optional_header : IMAGE_OPTIONAL_HEADER(file_header.SizeOfOptionalHeader, file_header.NumberOfSections) &length=file_header.SizeOfOptionalHeader;
} &byteorder=littleendian &length=file_header.SizeOfOptionalHeader+offsetof(optional_header);

type IMAGE_FILE_HEADER = record {
	Machine               : uint16;
	NumberOfSections      : uint16;
	TimeDateStamp         : uint32;
	PointerToSymbolTable  : uint32;
	NumberOfSymbols       : uint32;
	SizeOfOptionalHeader  : uint16;
	Characteristics       : uint16;
};

type IMAGE_OPTIONAL_HEADER(len: uint16, number_of_sections: uint16) = record {
	magic                   : uint16;
	major_linker_version    : uint8;
	minor_linker_version    : uint8;
	size_of_code            : uint32;
	size_of_init_data       : uint32;
	size_of_uninit_data     : uint32;
	addr_of_entry_point     : uint32;
	base_of_code            : uint32;
	base_of_data            : uint32;
	image_base              : uint32;
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
	mem: case magic of {
		267  -> i32           : MEM_INFO32;
		268  -> i64           : MEM_INFO64;
		default -> InvalidPEFile : empty;
	};
	loader_flags            : uint32;
	number_of_rva_and_sizes : uint32;
	rvas					: IMAGE_RVAS(number_of_rva_and_sizes);
} &byteorder=littleendian &length=len;

type MEM_INFO32 = record {
	size_of_stack_reserve : uint32;
	size_of_stack_commit  : uint32;
	size_of_heap_reserve  : uint32;
	size_of_heap_commit   : uint32;
} &byteorder=littleendian &length=16;

type MEM_INFO64 = record {
	size_of_stack_reserve : uint64;
	size_of_stack_commit  : uint64;
	size_of_heap_reserve  : uint64;
	size_of_heap_commit   : uint64;
} &byteorder=littleendian &length=32;

type IMAGE_SECTIONS(num: uint16) = record {
	sections : IMAGE_SECTION_HEADER[num];
} &length=num*40;

type IMAGE_SECTION_HEADER = record {
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
} &byteorder=littleendian &length=40;


type IMAGE_DATA_DIRECTORY = record {
	virtual_address : uint32;
	size            : uint16;
};

type IMAGE_IMPORT_DIRECTORY = record {
	rva_import_lookup_table : uint32;
	time_date_stamp         : uint32;
	forwarder_chain         : uint32;
	rva_module_name         : uint32;
	rva_import_addr_table   : uint32;
};

type IMAGE_RVAS(num: uint32) = record {
	rvas : IMAGE_RVA[num];
} &length=num*8;

type IMAGE_RVA = record {
	virtual_address : uint32;
	size			: uint32;
} &length=8;

type DATA_SECTIONS = record {
	blah: uint8;
};