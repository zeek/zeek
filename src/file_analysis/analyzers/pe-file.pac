
type TheFile = record {
	dos_header : DOS_Header;
	dos_code   : bytestring &length=(dos_header.AddressOfNewExeHeader - 64);
	pe_header  : IMAGE_NT_HEADERS;
	pad        : bytestring &length=1316134912 &transient;
} &let {
	dos_code_len: uint32 = (dos_header.AddressOfNewExeHeader - 64);
} &transient &byteorder=littleendian;

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

type IMAGE_NT_HEADERS = record {
	PESignature           : uint32;
	FileHeader            : IMAGE_FILE_HEADER;
	OptionalHeader        : OPTIONAL_HEADER(FileHeader.SizeOfOptionalHeader);
} &byteorder=littleendian &length=FileHeader.SizeOfOptionalHeader+offsetof(OptionalHeader);

type IMAGE_FILE_HEADER = record {
	Machine               : uint16;
	NumberOfSections      : uint16;
	TimeDateStamp         : uint32;
	PointerToSymbolTable  : uint32;
	NumberOfSymbols       : uint32;
	SizeOfOptionalHeader  : uint16;
	Characteristics       : uint16;
};

type OPTIONAL_HEADER(len: uint16) = record {
	OptionalHeaderMagic   : uint16;
	Header                : case OptionalHeaderMagic of {
		0x0b01  -> OptionalHeader32 : IMAGE_OPTIONAL_HEADER32;
		0x0b02  -> OptionalHeader64 : IMAGE_OPTIONAL_HEADER64;
		default -> InvalidPEFile    : bytestring &restofdata;
	};
} &length=len;

type IMAGE_OPTIONAL_HEADER32 = record {
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
	size_of_stack_reserve   : uint32;
	size_of_stack_commit    : uint32;
	size_of_heap_reserve    : uint32;
	size_of_heap_commit     : uint32;
	loader_flags            : uint32;
	number_of_rva_and_sizes : uint32;
} &byteorder=littleendian;

type IMAGE_OPTIONAL_HEADER64 = record {

} &byteorder=littleendian;
