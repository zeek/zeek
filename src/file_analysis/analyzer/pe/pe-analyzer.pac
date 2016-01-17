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
	VectorVal* rvas = new VectorVal(internal_type("index_vec")->AsVectorType());
	for ( uint16 i=0; i < rva_table->rvas()->size(); ++i )
		rvas->Assign(i, new Val((*rva_table->rvas())[i]->size(), TYPE_COUNT));

	return rvas;
	}
%}


refine flow File += {

	function characteristics_to_bro(c: uint32, len: uint8): TableVal
		%{
		uint64 mask = (len==16) ? 0xFFFF : 0xFFFFFFFF;
		TableVal* char_set = new TableVal(internal_type("count_set")->AsTableType());
		for ( uint16 i=0; i < len; ++i )
			{
			if ( ((c >> i) & 0x1) == 1 )
				{
				Val *ch = new Val((1<<i)&mask, TYPE_COUNT);
				char_set->Assign(ch, 0);
				Unref(ch);
				}
			}
		return char_set;
		%}

	function proc_dos_header(h: DOS_Header): bool
		%{
		if ( pe_dos_header )
			{
			RecordVal* dh = new RecordVal(BifType::Record::PE::DOSHeader);
			dh->Assign(0, new StringVal(${h.signature}.length(), (const char*) ${h.signature}.data()));
			dh->Assign(1, new Val(${h.UsedBytesInTheLastPage}, TYPE_COUNT));
			dh->Assign(2, new Val(${h.FileSizeInPages}, TYPE_COUNT));
			dh->Assign(3, new Val(${h.NumberOfRelocationItems}, TYPE_COUNT));
			dh->Assign(4, new Val(${h.HeaderSizeInParagraphs}, TYPE_COUNT));
			dh->Assign(5, new Val(${h.MinimumExtraParagraphs}, TYPE_COUNT));
			dh->Assign(6, new Val(${h.MaximumExtraParagraphs}, TYPE_COUNT));
			dh->Assign(7, new Val(${h.InitialRelativeSS}, TYPE_COUNT));
			dh->Assign(8, new Val(${h.InitialSP}, TYPE_COUNT));
			dh->Assign(9, new Val(${h.Checksum}, TYPE_COUNT));
			dh->Assign(10, new Val(${h.InitialIP}, TYPE_COUNT));
			dh->Assign(11, new Val(${h.InitialRelativeCS}, TYPE_COUNT));
			dh->Assign(12, new Val(${h.AddressOfRelocationTable}, TYPE_COUNT));
			dh->Assign(13, new Val(${h.OverlayNumber}, TYPE_COUNT));
			dh->Assign(14, new Val(${h.OEMid}, TYPE_COUNT));
			dh->Assign(15, new Val(${h.OEMinfo}, TYPE_COUNT));
			dh->Assign(16, new Val(${h.AddressOfNewExeHeader}, TYPE_COUNT));

			BifEvent::generate_pe_dos_header((analyzer::Analyzer *) connection()->bro_analyzer(),
			                                 connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
			                                 dh);
			}
		return true;
		%}

	function proc_dos_code(code: bytestring): bool
		%{
		if ( pe_dos_code )
			{
			BifEvent::generate_pe_dos_code((analyzer::Analyzer *) connection()->bro_analyzer(),
			                               connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
			                               new StringVal(code.length(), (const char*) code.data()));
			}
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
			RecordVal* fh = new RecordVal(BifType::Record::PE::FileHeader);
			fh->Assign(0, new Val(${h.Machine}, TYPE_COUNT));
			fh->Assign(1, new Val(static_cast<double>(${h.TimeDateStamp}), TYPE_TIME));
			fh->Assign(2, new Val(${h.PointerToSymbolTable}, TYPE_COUNT));
			fh->Assign(3, new Val(${h.NumberOfSymbols}, TYPE_COUNT));
			fh->Assign(4, new Val(${h.SizeOfOptionalHeader}, TYPE_COUNT));
			fh->Assign(5, characteristics_to_bro(${h.Characteristics}, 16));
			BifEvent::generate_pe_file_header((analyzer::Analyzer *) connection()->bro_analyzer(),
			                                  connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
			                                  fh);
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
			RecordVal* oh = new RecordVal(BifType::Record::PE::OptionalHeader);

			oh->Assign(0, new Val(${h.magic}, TYPE_COUNT));
			oh->Assign(1, new Val(${h.major_linker_version}, TYPE_COUNT));
			oh->Assign(2, new Val(${h.minor_linker_version}, TYPE_COUNT));
			oh->Assign(3, new Val(${h.size_of_code}, TYPE_COUNT));
			oh->Assign(4, new Val(${h.size_of_init_data}, TYPE_COUNT));
			oh->Assign(5, new Val(${h.size_of_uninit_data}, TYPE_COUNT));
			oh->Assign(6, new Val(${h.addr_of_entry_point}, TYPE_COUNT));
			oh->Assign(7, new Val(${h.base_of_code}, TYPE_COUNT));

			if ( ${h.pe_format} != PE32_PLUS )
				oh->Assign(8, new Val(${h.base_of_data}, TYPE_COUNT));

			oh->Assign(9, new Val(${h.image_base}, TYPE_COUNT));
			oh->Assign(10, new Val(${h.section_alignment}, TYPE_COUNT));
			oh->Assign(11, new Val(${h.file_alignment}, TYPE_COUNT));
			oh->Assign(12, new Val(${h.os_version_major}, TYPE_COUNT));
			oh->Assign(13, new Val(${h.os_version_minor}, TYPE_COUNT));
			oh->Assign(14, new Val(${h.major_image_version}, TYPE_COUNT));
			oh->Assign(15, new Val(${h.minor_image_version}, TYPE_COUNT));
			oh->Assign(16, new Val(${h.minor_subsys_version}, TYPE_COUNT));
			oh->Assign(17, new Val(${h.minor_subsys_version}, TYPE_COUNT));
			oh->Assign(18, new Val(${h.size_of_image}, TYPE_COUNT));
			oh->Assign(19, new Val(${h.size_of_headers}, TYPE_COUNT));
			oh->Assign(20, new Val(${h.checksum}, TYPE_COUNT));
			oh->Assign(21, new Val(${h.subsystem}, TYPE_COUNT));
			oh->Assign(22, characteristics_to_bro(${h.dll_characteristics}, 16));

			oh->Assign(23, process_rvas(${h.rvas}));

			BifEvent::generate_pe_optional_header((analyzer::Analyzer *) connection()->bro_analyzer(),
			                                      connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
			                                      oh);
			}
		return true;
		%}

	function proc_section_header(h: Section_Header): bool
		%{
		if ( pe_section_header )
			{
			RecordVal* section_header = new RecordVal(BifType::Record::PE::SectionHeader);

			// Strip null characters from the end of the section name.
			u_char* first_null = (u_char*) memchr(${h.name}.data(), 0, ${h.name}.length());
			uint16 name_len;
			if ( first_null == NULL )
				name_len = ${h.name}.length();
			else
				name_len = first_null - ${h.name}.data();
			section_header->Assign(0, new StringVal(name_len, (const char*) ${h.name}.data()));

			section_header->Assign(1, new Val(${h.virtual_size}, TYPE_COUNT));
			section_header->Assign(2, new Val(${h.virtual_addr}, TYPE_COUNT));
			section_header->Assign(3, new Val(${h.size_of_raw_data}, TYPE_COUNT));
			section_header->Assign(4, new Val(${h.ptr_to_raw_data}, TYPE_COUNT));
			section_header->Assign(5, new Val(${h.non_used_ptr_to_relocs}, TYPE_COUNT));
			section_header->Assign(6, new Val(${h.non_used_ptr_to_line_nums}, TYPE_COUNT));
			section_header->Assign(7, new Val(${h.non_used_num_of_relocs}, TYPE_COUNT));
			section_header->Assign(8, new Val(${h.non_used_num_of_line_nums}, TYPE_COUNT));
			section_header->Assign(9, characteristics_to_bro(${h.characteristics}, 32));

			BifEvent::generate_pe_section_header((analyzer::Analyzer *) connection()->bro_analyzer(),
			                                     connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
			                                     section_header);
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
