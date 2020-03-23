%extern{
#include "Desc.h"
#include "file_analysis/Manager.h"
#include "types.bif.h"
%}

refine flow RDPEUDP_Flow += {
	function proc_rdpeudp_established(): bool
		%{
		if ( is_established )
			{
			BifEvent::generate_rdpeudp_established(connection()->bro_analyzer(),
			                                       connection()->bro_analyzer()->Conn());
			}
		return true;
		%}
};

refine typeattr RDPEUDPPDU_SYNACK += &let {
	proc: bool = $context.flow.proc_rdpeudp_established(this);
};
