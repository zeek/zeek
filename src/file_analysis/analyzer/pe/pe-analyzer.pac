%extern{
#include "Event.h"
#include "file_analysis/File.h"
#include "events.bif.h"
%}

%header{
VectorVal* process_rvas(const RVAS* rvas);
%}

%code{
VectorVal* process_rvas(const RVAS* rva_table)
	{
	auto rvas = make_intrusive<VectorVal>(zeek::id::index_vec);

	for ( uint16 i=0; i < rva_table->rvas()->size(); ++i )
		rvas->Assign(i, val_mgr->Count((*rva_table->rvas())[i]->size()));

	return rvas.release();
	}
%}


refine flow File += {

	function characteristics_to_bro(c: uint32, len: uint8): TableVal
		%{
		uint64 mask = (len==16) ? 0xFFFF : 0xFFFFFFFF;
		TableVal* char_set = new TableVal(zeek::id::count_set);
		for ( uint16 i=0; i < len; ++i )
			{
			if ( ((c >> i) & 0x1) == 1 )
				{
				auto ch = val_mgr->Count((1<<i)&mask);
				char_set->Assign(ch.get(), 0);
				}
			}
		return char_set;
		%}

	function proc_dos_header(h: DOS_Header): bool
		%{
		if ( pe_dos_header )
			{
			auto dh = make_intrusive<RecordVal>(BifType::Record::PE::DOSHeader);
			dh->Assign(0, make_intrusive<StringVal>(${h.signature}.length(), (const char*) ${h.signature}.data()));
			dh->Assign(1, val_mgr->Count(${h.UsedBytesInTheLastPage}));
			dh->Assign(2, val_mgr->Count(${h.FileSizeInPages}));
			dh->Assign(3, val_mgr->Count(${h.NumberOfRelocationItems}));
			dh->Assign(4, val_mgr->Count(${h.HeaderSizeInParagraphs}));
			dh->Assign(5, val_mgr->Count(${h.MinimumExtraParagraphs}));
			dh->Assign(6, val_mgr->Count(${h.MaximumExtraParagraphs}));
			dh->Assign(7, val_mgr->Count(${h.InitialRelativeSS}));
			dh->Assign(8, val_mgr->Count(${h.InitialSP}));
			dh->Assign(9, val_mgr->Count(${h.Checksum}));
			dh->Assign(10, val_mgr->Count(${h.InitialIP}));
			dh->Assign(11, val_mgr->Count(${h.InitialRelativeCS}));
			dh->Assign(12, val_mgr->Count(${h.AddressOfRelocationTable}));
			dh->Assign(13, val_mgr->Count(${h.OverlayNumber}));
			dh->Assign(14, val_mgr->Count(${h.OEMid}));
			dh->Assign(15, val_mgr->Count(${h.OEMinfo}));
			dh->Assign(16, val_mgr->Count(${h.AddressOfNewExeHeader}));

			mgr.Enqueue(pe_dos_header,
			    IntrusivePtr{NewRef{}, connection()->bro_analyzer()->GetFile()->GetVal()},
			    std::move(dh));
			}
		return true;
		%}

	function proc_dos_code(code: bytestring): bool
		%{
		if ( pe_dos_code )
			mgr.Enqueue(pe_dos_code,
			    IntrusivePtr{NewRef{}, connection()->bro_analyzer()->GetFile()->GetVal()},
			    make_intrusive<StringVal>(code.length(), (const char*) code.data())
			    );
		return true;
		%}

	function proc_nt_headers(h: NT_Headers): bool
		%{
		if ( ${h.PESignature} != 17744 ) // Number is uint32 version of "PE\0\0"
			{
			return false;
			// FileViolation("PE Header signature is incorrect.");
			}
		return true;
		%}

	function proc_file_header(h: File_Header): bool
		%{
		if ( pe_file_header )
			{
			auto fh = make_intrusive<RecordVal>(BifType::Record::PE::FileHeader);
			fh->Assign(0, val_mgr->Count(${h.Machine}));
			fh->Assign(1, make_intrusive<Val>(static_cast<double>(${h.TimeDateStamp}), TYPE_TIME));
			fh->Assign(2, val_mgr->Count(${h.PointerToSymbolTable}));
			fh->Assign(3, val_mgr->Count(${h.NumberOfSymbols}));
			fh->Assign(4, val_mgr->Count(${h.SizeOfOptionalHeader}));
			fh->Assign(5, characteristics_to_bro(${h.Characteristics}, 16));

			mgr.Enqueue(pe_file_header,
			    IntrusivePtr{NewRef{}, connection()->bro_analyzer()->GetFile()->GetVal()},
			    std::move(fh));
			}

		return true;
		%}

	function proc_optional_header(h: Optional_Header): bool
		%{
		if ( ${h.magic} != 0x10b &&  // normal pe32 executable
		     ${h.magic} != 0x107 &&  // rom image
		     ${h.magic} != 0x20b )   // pe32+ executable
			{
			// FileViolation("PE Optional Header magic is invalid.");
			return false;
			}

		if ( pe_optional_header )
			{
			auto oh = make_intrusive<RecordVal>(BifType::Record::PE::OptionalHeader);

			oh->Assign(0, val_mgr->Count(${h.magic}));
			oh->Assign(1, val_mgr->Count(${h.major_linker_version}));
			oh->Assign(2, val_mgr->Count(${h.minor_linker_version}));
			oh->Assign(3, val_mgr->Count(${h.size_of_code}));
			oh->Assign(4, val_mgr->Count(${h.size_of_init_data}));
			oh->Assign(5, val_mgr->Count(${h.size_of_uninit_data}));
			oh->Assign(6, val_mgr->Count(${h.addr_of_entry_point}));
			oh->Assign(7, val_mgr->Count(${h.base_of_code}));

			if ( ${h.pe_format} != PE32_PLUS )
				oh->Assign(8, val_mgr->Count(${h.base_of_data}));

			oh->Assign(9, val_mgr->Count(${h.image_base}));
			oh->Assign(10, val_mgr->Count(${h.section_alignment}));
			oh->Assign(11, val_mgr->Count(${h.file_alignment}));
			oh->Assign(12, val_mgr->Count(${h.os_version_major}));
			oh->Assign(13, val_mgr->Count(${h.os_version_minor}));
			oh->Assign(14, val_mgr->Count(${h.major_image_version}));
			oh->Assign(15, val_mgr->Count(${h.minor_image_version}));
			oh->Assign(16, val_mgr->Count(${h.minor_subsys_version}));
			oh->Assign(17, val_mgr->Count(${h.minor_subsys_version}));
			oh->Assign(18, val_mgr->Count(${h.size_of_image}));
			oh->Assign(19, val_mgr->Count(${h.size_of_headers}));
			oh->Assign(20, val_mgr->Count(${h.checksum}));
			oh->Assign(21, val_mgr->Count(${h.subsystem}));
			oh->Assign(22, characteristics_to_bro(${h.dll_characteristics}, 16));

			oh->Assign(23, process_rvas(${h.rvas}));

			mgr.Enqueue(pe_optional_header,
			    IntrusivePtr{NewRef{}, connection()->bro_analyzer()->GetFile()->GetVal()},
			    std::move(oh));
			}
		return true;
		%}

	function proc_section_header(h: Section_Header): bool
		%{
		if ( pe_section_header )
			{
			auto section_header = make_intrusive<RecordVal>(BifType::Record::PE::SectionHeader);

			// Strip null characters from the end of the section name.
			u_char* first_null = (u_char*) memchr(${h.name}.data(), 0, ${h.name}.length());
			uint16 name_len;
			if ( first_null == NULL )
				name_len = ${h.name}.length();
			else
				name_len = first_null - ${h.name}.data();
			section_header->Assign(0, make_intrusive<StringVal>(name_len, (const char*) ${h.name}.data()));

			section_header->Assign(1, val_mgr->Count(${h.virtual_size}));
			section_header->Assign(2, val_mgr->Count(${h.virtual_addr}));
			section_header->Assign(3, val_mgr->Count(${h.size_of_raw_data}));
			section_header->Assign(4, val_mgr->Count(${h.ptr_to_raw_data}));
			section_header->Assign(5, val_mgr->Count(${h.non_used_ptr_to_relocs}));
			section_header->Assign(6, val_mgr->Count(${h.non_used_ptr_to_line_nums}));
			section_header->Assign(7, val_mgr->Count(${h.non_used_num_of_relocs}));
			section_header->Assign(8, val_mgr->Count(${h.non_used_num_of_line_nums}));
			section_header->Assign(9, characteristics_to_bro(${h.characteristics}, 32));

			mgr.Enqueue(pe_section_header,
			    IntrusivePtr{NewRef{}, connection()->bro_analyzer()->GetFile()->GetVal()},
			    std::move(section_header)
			    );
			}
		return true;
		%}
};

refine typeattr DOS_Header += &let {
	proc : bool = $context.flow.proc_dos_header(this);
};

refine typeattr DOS_Code += &let {
	proc : bool = $context.flow.proc_dos_code(code);
};

refine typeattr NT_Headers += &let {
	proc : bool = $context.flow.proc_nt_headers(this);
};

refine typeattr File_Header += &let {
	proc : bool = $context.flow.proc_file_header(this);
};

refine typeattr Optional_Header += &let {
	proc : bool = $context.flow.proc_optional_header(this);
};

refine typeattr Section_Header += &let {
	proc: bool = $context.flow.proc_section_header(this);
};
