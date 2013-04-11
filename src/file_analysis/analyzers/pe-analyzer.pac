
%extern{
#include "Event.h"
#include "file_analysis.bif.func_h"
%}

refine flow File += {

	function proc_dos_header(h: DOS_Header) : bool
		%{
		BifEvent::FileAnalysis::generate_windows_pe_dosstub((Analyzer *) connection()->bro_analyzer(), 
		                                                    //(Val *) connection()->bro_analyzer()->GetInfo(),
		                                                    //new StringVal(${h.signature}.length(), (const char*) ${h.signature}.begin()),
		                                                    ${h.AddressOfNewExeHeader}-64);
		return true;
		%}

	function proc_pe_header(h: IMAGE_NT_HEADERS) : bool
		%{
		BifEvent::FileAnalysis::generate_windows_pe_timestamp((Analyzer *) connection()->bro_analyzer(), 
		                                                    //(Val *) connection()->bro_analyzer()->GetInfo(),
		                                                    //new StringVal(${h.signature}.length(), (const char*) ${h.signature}.begin()),
		                                                    ${h.FileHeader.TimeDateStamp});
		return true;
		%}
};

refine typeattr DOS_Header += &let {
	proc : bool = $context.flow.proc_dos_header(this);
};

refine typeattr IMAGE_NT_HEADERS += &let {
	proc : bool = $context.flow.proc_pe_header(this);
};

