# The base record for a Portable Executable file
type PE_File = record {
	headers         : Headers;
	pad		: Padding(iat_loc);
	iat		: IMPORT_ADDRESS_TABLE &length=$context.connection.get_import_table_len();
} &let {
	unparsed_hdr_len: uint32 = headers.pe_header.optional_header.size_of_headers - headers.length;
	iat_loc: uint32 = $context.connection.get_import_table_addr() - headers.pe_header.optional_header.size_of_headers + unparsed_hdr_len;
	
} &byteorder=littleendian;

## Headers

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
} &byteorder=littleendian &length=64;

type DOS_Code(len: uint32) = record {
	code : bytestring &length=len;
};

# The NT headers give us the file and the optional headers.
type NT_Headers = record {
	PESignature     : uint32;
	file_header     : File_Header;
	optional_header : Optional_Header(file_header.SizeOfOptionalHeader, file_header.NumberOfSections) &length=file_header.SizeOfOptionalHeader;
} &let {
	length: uint32 = file_header.SizeOfOptionalHeader+offsetof(optional_header);
} &byteorder=littleendian &length=length;

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
type Optional_Header(len: uint16, number_of_sections: uint16) = record {
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
		267  -> i32           : Mem_Info32;
		268  -> i64           : Mem_Info64;
		default -> InvalidPEFile : empty;
	};
	loader_flags            : uint32;
	number_of_rva_and_sizes : uint32;
	rvas			: RVAS(number_of_rva_and_sizes);
} &byteorder=littleendian &length=len;

type Mem_Info32 = record {
	size_of_stack_reserve : uint32;
	size_of_stack_commit  : uint32;
	size_of_heap_reserve  : uint32;
	size_of_heap_commit   : uint32;
} &byteorder=littleendian &length=16;

type Mem_Info64 = record {
	size_of_stack_reserve : uint64;
	size_of_stack_commit  : uint64;
	size_of_heap_reserve  : uint64;
	size_of_heap_commit   : uint64;
} &byteorder=littleendian &length=32;

type RVAS(num: uint32) = record {
	rvas : RVA[num];
};

type RVA = record {
	virtual_address : uint32;
	size		: uint32;
} &let {
	proc: bool = $context.connection.proc_rva(this);
} &length=8;

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
	proc: bool = $context.connection.proc_section(this);
} &byteorder=littleendian &length=40;

## The BinPAC padding type doens't work here.

type Padding(length: uint32) = record {
	blah: bytestring &length=length &transient;
};

## Support for parsing the .idata section

type IMAGE_IMPORT_DIRECTORY = record {
	rva_import_lookup_table : uint32;
	time_date_stamp         : uint32;
	forwarder_chain         : uint32;
	rva_module_name         : uint32;
	rva_import_addr_table   : uint32;
} &let {
	is_null: bool = rva_module_name == 0;
	proc: bool = $context.connection.proc_image_import_directory(this);
} &length=20;

type IMPORT_LOOKUP_ATTRS = record {
	attrs: uint32;
} &let {
	is_null: bool = attrs == 0;
} &length=4;

type IMPORT_LOOKUP_TABLE = record {
	attrs: IMPORT_LOOKUP_ATTRS[] &until($element.is_null);
} &let {
	proc: bool = $context.connection.proc_import_lookup_table(this);
};

#type null_terminated_string = RE/[^\x00]+\x00/;
type null_terminated_string = RE/[A-Za-z0-9.]+\x00/;

type IMPORT_ENTRY(is_module: bool, pad_align: uint8) = case is_module of {
	true  -> module: IMPORT_MODULE(pad_align);
	false -> hint:   IMPORT_HINT(pad_align);
};

type IMPORT_MODULE(pad_align: uint8) = record {
	pad: bytestring &length=pad_align;
	name: null_terminated_string;	
} &let {
	proc: bool = $context.connection.proc_import_module(this);
};

type IMPORT_HINT(pad_align: uint8) = record {
	pad: bytestring &length=pad_align;
	index: uint16;
	name: null_terminated_string;
} &let {
	proc: bool = $context.connection.proc_import_hint(this);
	last: bool = sizeof(name) == 0;
};

type IMPORT_ADDRESS_TABLE = record {
	directory_table : IMAGE_IMPORT_DIRECTORY[] &until $element.is_null;
	lookup_tables   : IMPORT_LOOKUP_TABLE[] &until $context.connection.get_num_imports() <= 0;
	hint_table	: IMPORT_ENTRY($context.connection.get_next_hint_type(), $context.connection.get_next_hint_align())[] &until($context.connection.imports_done());
} &let {
	proc: bool = $context.connection.proc_iat(this);
};

refine connection MockConnection += {
	%member{
		uint8 rvas_seen_;
		uint8 num_imports_;
		uint32 rva_offset_;

		bool has_import_table_;
		uint32 import_table_va_;
		uint32 import_table_rva_;
		uint32 import_table_len_;
		vector<uint32> imports_per_module_;
		uint32 next_hint_index_;
		uint8 next_hint_align_;
		bool next_hint_is_module_;

		bool has_export_table_;
		uint32 export_table_va_;
		uint32 export_table_rva_;
	%}

	%init{
		rvas_seen_ = 0;
		rva_offset_ = 0;
		num_imports_ = -1;
		has_import_table_ = false;
		has_export_table_ = false;

		next_hint_is_module_ = true;
		next_hint_index_ = 0;
		next_hint_align_ = 0;
	%}

	function proc_rva(r: RVA): bool
		%{
		if ( rvas_seen_ == 1 )
			{
			has_import_table_ = ${r.virtual_address} > 0;
			if ( has_import_table_ ) {
				import_table_rva_ = ${r.virtual_address};
				import_table_len_ = ${r.size};
				}
			}
		if ( rvas_seen_ == 2 )
			{
			has_export_table_ = ${r.virtual_address} > 0;
			if ( has_export_table_ )
				export_table_rva_ = ${r.virtual_address};
			}
		++rvas_seen_;
		return true;
		%}

	function proc_section(h: Section_Header): bool
		%{
		if ( has_import_table_ && ${h.virtual_addr} == import_table_rva_ ){
			printf("Found import table %d\n", ${h.ptr_to_raw_data});
			rva_offset_ = ${h.virtual_addr} - ${h.ptr_to_raw_data};

			import_table_va_ = ${h.ptr_to_raw_data};
			get_import_table_addr();
			}
		if ( has_export_table_ && ${h.virtual_addr} == export_table_rva_ )
			export_table_va_ = ${h.ptr_to_raw_data};
		return true;
		%}

	function proc_image_import_directory(i: IMAGE_IMPORT_DIRECTORY): bool
		%{
		num_imports_++;
		return true;
		%}

	function proc_iat(i: IMPORT_ADDRESS_TABLE): bool
		%{
		printf("IAT processed\n");
		return true;
		%}

	function get_import_table_addr(): uint32
		%{
		return has_import_table_ ? import_table_va_ : 0;
		%}

	function get_import_table_len(): uint32
		%{
		return has_import_table_ ? import_table_len_ : 0;
		%}

	function get_rva_offset(): uint32
		%{
		return rva_offset_;
		%}

	function get_num_imports(): uint8
		%{
		return num_imports_;
		%}		

	function get_next_hint_align(): uint8
		%{
		return next_hint_align_;
		%}		

	function proc_import_lookup_table(t: IMPORT_LOOKUP_TABLE): bool
		%{
		--num_imports_;
		imports_per_module_.push_back(${t.attrs}->size());
		return true;
		%}		

	function get_next_hint_type(): bool
		%{
		if ( next_hint_is_module_ )
			{
			next_hint_is_module_ = false;
			return true;
			}
		if ( --imports_per_module_[next_hint_index_] == 0)
			{
			++next_hint_index_;
			return true;
			}
		return false;
		%}

	function imports_done(): bool
		%{
		return next_hint_index_ == imports_per_module_.size();
		%}

	function proc_import_hint(h: IMPORT_HINT): bool
		%{
		printf("        Imported function '%s'\n", ${h.name}.data());
		next_hint_align_ = ${h.name}.length() % 2;
		return true;
		%}

	function proc_import_module(m: IMPORT_MODULE): bool
		%{
		printf("Imported module '%s'\n", ${m.name}.data());
		next_hint_align_ = ${m.name}.length() % 2;
		return true;
		%}
};