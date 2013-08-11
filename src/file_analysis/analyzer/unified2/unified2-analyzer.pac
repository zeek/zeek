%extern{
#include "Event.h"
#include "file_analysis/File.h"
#include "events.bif.h"
%}

refine flow Flow += {

	%member{
	%}

	%init{
	%}

	%eof{
	%}

	%cleanup{
	%}

	function proc_ids_event(ev: IDSEvent) : bool
		%{
		val_list* vl = new val_list();
		vl->append(connection()->bro_analyzer()->GetFile()->GetVal()->Ref());
		vl->append(new Val(${ev.signature_id}, TYPE_COUNT));
		mgr.QueueEvent(::unified2_alert, vl, SOURCE_LOCAL);

		return true;
		%}
};


refine typeattr IDSEvent += &let {
	proc : bool = $context.flow.proc_ids_event(this);
};
