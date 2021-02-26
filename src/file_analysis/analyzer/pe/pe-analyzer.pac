%extern{
#include "zeek/Event.h"
#include "zeek/file_analysis/File.h"

#include "zeek/file_analysis/analyzer/pe/events.bif.h"
%}

%header{
zeek::VectorValPtr process_rvas(const RVAS* rvas);
zeek::TableValPtr characteristics_to_zeek(uint32_t c, uint8_t len);
%}

%code{
zeek::VectorValPtr process_rvas(const RVAS* rva_table)
	{
	auto rvas = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);

	for ( size_t i=0; i < rva_table->rvas()->size(); ++i )
		rvas->Assign(i, zeek::val_mgr->Count((*rva_table->rvas())[i]->size()));

	return rvas;
	}

zeek::TableValPtr characteristics_to_zeek(uint32_t c, uint8_t len)
	{
	uint64 mask = (len==16) ? 0xFFFF : 0xFFFFFFFF;
	auto char_set = zeek::make_intrusive<zeek::TableVal>(zeek::id::count_set);

	for ( uint16 i=0; i < len; ++i )
		{
		if ( ((c >> i) & 0x1) == 1 )
			{
			auto ch = zeek::val_mgr->Count((1<<i)&mask);
			char_set->Assign(std::move(ch), 0);
			}
		}

	return char_set;
	}
%}


refine flow File += {


	function proc_dos_header(h: DOS_Header): bool
		%{
		if ( pe_dos_header )
			{
			auto dh = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::PE::DOSHeader);
			dh->Assign(0, zeek::make_intrusive<zeek::StringVal>(${h.signature}.length(), (const char*) ${h.signature}.data()));
			dh->Assign(1, ${h.UsedBytesInTheLastPage});
			dh->Assign(2, ${h.FileSizeInPages});
			dh->Assign(3, ${h.NumberOfRelocationItems});
			dh->Assign(4, ${h.HeaderSizeInParagraphs});
			dh->Assign(5, ${h.MinimumExtraParagraphs});
			dh->Assign(6, ${h.MaximumExtraParagraphs});
			dh->Assign(7, ${h.InitialRelativeSS});
			dh->Assign(8, ${h.InitialSP});
			dh->Assign(9, ${h.Checksum});
			dh->Assign(10, ${h.InitialIP});
			dh->Assign(11, ${h.InitialRelativeCS});
			dh->Assign(12, ${h.AddressOfRelocationTable});
			dh->Assign(13, ${h.OverlayNumber});
			dh->Assign(14, ${h.OEMid});
			dh->Assign(15, ${h.OEMinfo});
			dh->Assign(16, ${h.AddressOfNewExeHeader});

			zeek::event_mgr.Enqueue(pe_dos_header,
			    connection()->zeek_analyzer()->GetFile()->ToVal(),
			    std::move(dh));
			}
		return true;
		%}

	function proc_dos_code(code: bytestring): bool
		%{
		if ( pe_dos_code )
			zeek::event_mgr.Enqueue(pe_dos_code,
			    connection()->zeek_analyzer()->GetFile()->ToVal(),
			    zeek::make_intrusive<zeek::StringVal>(code.length(), (const char*) code.data())
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
			auto fh = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::PE::FileHeader);
			fh->Assign(0, ${h.Machine});
			fh->AssignTime(1, double(${h.TimeDateStamp}));
			fh->Assign(2, ${h.PointerToSymbolTable});
			fh->Assign(3, ${h.NumberOfSymbols});
			fh->Assign(4, ${h.SizeOfOptionalHeader});
			fh->Assign(5, characteristics_to_zeek(${h.Characteristics}, 16));

			zeek::event_mgr.Enqueue(pe_file_header,
			    connection()->zeek_analyzer()->GetFile()->ToVal(),
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
			auto oh = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::PE::OptionalHeader);

			oh->Assign(0, ${h.magic});
			oh->Assign(1, ${h.major_linker_version});
			oh->Assign(2, ${h.minor_linker_version});
			oh->Assign(3, ${h.size_of_code});
			oh->Assign(4, ${h.size_of_init_data});
			oh->Assign(5, ${h.size_of_uninit_data});
			oh->Assign(6, ${h.addr_of_entry_point});
			oh->Assign(7, ${h.base_of_code});

			if ( ${h.pe_format} != PE32_PLUS )
				oh->Assign(8, ${h.base_of_data});

			oh->Assign(9, ${h.image_base});
			oh->Assign(10, ${h.section_alignment});
			oh->Assign(11, ${h.file_alignment});
			oh->Assign(12, ${h.os_version_major});
			oh->Assign(13, ${h.os_version_minor});
			oh->Assign(14, ${h.major_image_version});
			oh->Assign(15, ${h.minor_image_version});
			oh->Assign(16, ${h.major_subsys_version});
			oh->Assign(17, ${h.minor_subsys_version});
			oh->Assign(18, ${h.size_of_image});
			oh->Assign(19, ${h.size_of_headers});
			oh->Assign(20, ${h.checksum});
			oh->Assign(21, ${h.subsystem});
			oh->Assign(22, characteristics_to_zeek(${h.dll_characteristics}, 16));

			oh->Assign(23, process_rvas(${h.rvas}));

			zeek::event_mgr.Enqueue(pe_optional_header,
			    connection()->zeek_analyzer()->GetFile()->ToVal(),
			    std::move(oh));
			}
		return true;
		%}

	function proc_section_header(h: Section_Header): bool
		%{
		if ( pe_section_header )
			{
			auto section_header = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::PE::SectionHeader);

			// Strip null characters from the end of the section name.
			u_char* first_null = (u_char*) memchr(${h.name}.data(), 0, ${h.name}.length());
			uint16 name_len;
			if ( first_null == NULL )
				name_len = ${h.name}.length();
			else
				name_len = first_null - ${h.name}.data();
			section_header->Assign(0, zeek::make_intrusive<zeek::StringVal>(name_len, (const char*) ${h.name}.data()));

			section_header->Assign(1, ${h.virtual_size});
			section_header->Assign(2, ${h.virtual_addr});
			section_header->Assign(3, ${h.size_of_raw_data});
			section_header->Assign(4, ${h.ptr_to_raw_data});
			section_header->Assign(5, ${h.non_used_ptr_to_relocs});
			section_header->Assign(6, ${h.non_used_ptr_to_line_nums});
			section_header->Assign(7, ${h.non_used_num_of_relocs});
			section_header->Assign(8, ${h.non_used_num_of_line_nums});
			section_header->Assign(9, characteristics_to_zeek(${h.characteristics}, 32));

			zeek::event_mgr.Enqueue(pe_section_header,
			    connection()->zeek_analyzer()->GetFile()->ToVal(),
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
