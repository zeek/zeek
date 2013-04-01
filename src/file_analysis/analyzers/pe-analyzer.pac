
%extern{
#include "Event.h"
#include "file_analysis.bif.func_h"
%}

refine flow File += {

	function proc_sig(sig: bytestring) : bool
		%{
		//val_list* vl = new val_list;
		//StringVal *sigval = new StringVal(${sig}.length(), (const char*) ${sig}.begin());
		//vl->append(sigval);
		//mgr.QueueEvent(FileAnalysis::windows_pe_sig, vl);

		BifEvent::FileAnalysis::generate_windows_pe_sig((Analyzer *) connection()->bro_analyzer(), 
		                                                (Val *) connection()->bro_analyzer()->GetInfo(),
		                                                new StringVal(${sig}.length(), (const char*) ${sig}.begin()));
		return true;
		%}

};

refine typeattr DOSStub += &let {
	proc : bool = $context.flow.proc_sig(signature);
};
