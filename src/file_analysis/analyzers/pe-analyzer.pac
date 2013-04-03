
%extern{
#include "Event.h"
#include "file_analysis.bif.func_h"
%}

refine flow File += {

	function proc_dosstub(stub: DOSStub) : bool
		%{
		BifEvent::FileAnalysis::generate_windows_pe_dosstub((Analyzer *) connection()->bro_analyzer(), 
		                                                    //(Val *) connection()->bro_analyzer()->GetInfo(),
		                                                    //new StringVal(${stub.signature}.length(), (const char*) ${stub.signature}.begin()),
		                                                    ${stub.HeaderSizeInParagraphs});
		return true;
		%}

};

refine typeattr DOSStub += &let {
	proc : bool = $context.flow.proc_dosstub(this);
};
