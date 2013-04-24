
%extern{
#include "Event.h"
#include "file_analysis/File.h"
#include "file_analysis.bif.func_h"
%}

refine flow File += {

	function proc_the_file(): bool
		%{
		printf("ending the flow!\n");
		connection()->bro_analyzer()->EndOfFile();
		connection()->FlowEOF(true);
		connection()->FlowEOF(false);
		return true;
		%}

	function proc_dos_header(h: DOS_Header): bool
		%{
		BifEvent::generate_file_pe_dosstub((Analyzer *) connection()->bro_analyzer(), 
		                                   connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
		                                   ${h.AddressOfNewExeHeader}-64);
		return true;
		%}

	function proc_pe_header(h: IMAGE_NT_HEADERS): bool
		%{
		BifEvent::generate_file_pe_timestamp((Analyzer *) connection()->bro_analyzer(), 
		                                     connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
		                                     ${h.file_header.TimeDateStamp});
		return true;
		%}


	function proc_section_header(h: IMAGE_SECTION_HEADER): bool
		%{
		RecordVal* section_header = new RecordVal(BifType::Record::PESectionHeader);
		section_header->Assign(0, new StringVal(${h.name}.length(), (const char*) ${h.name}.data()));
		section_header->Assign(1, new Val(${h.virtual_size}, TYPE_COUNT));
		section_header->Assign(2, new Val(${h.virtual_addr}, TYPE_COUNT));
		section_header->Assign(3, new Val(${h.size_of_raw_data}, TYPE_COUNT));
		section_header->Assign(4, new Val(${h.ptr_to_raw_data}, TYPE_COUNT));
		section_header->Assign(5, new Val(${h.non_used_ptr_to_relocs}, TYPE_COUNT));
		section_header->Assign(6, new Val(${h.non_used_ptr_to_line_nums}, TYPE_COUNT));
		section_header->Assign(7, new Val(${h.non_used_num_of_relocs}, TYPE_COUNT));
		section_header->Assign(8, new Val(${h.non_used_num_of_line_nums}, TYPE_COUNT));
		section_header->Assign(9, new Val(${h.characteristics}, TYPE_COUNT));

		BifEvent::generate_file_pe_section_header((Analyzer *) connection()->bro_analyzer(), 
		                                          connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
		                                          section_header);
		return true;
		%}
};

refine typeattr DOS_Header += &let {
	proc : bool = $context.flow.proc_dos_header(this);
};

refine typeattr IMAGE_NT_HEADERS += &let {
	proc : bool = $context.flow.proc_pe_header(this);
};

refine typeattr IMAGE_SECTION_HEADER += &let {
	proc: bool = $context.flow.proc_section_header(this);
};

refine typeattr TheFile += &let {
	proc: bool = $context.flow.proc_the_file();
};