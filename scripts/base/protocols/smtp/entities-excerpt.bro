##! This script is for optionally adding a body excerpt to the SMTP
##! entities log.

@load ./entities

module SMTP;

export {
	redef record SMTP::EntityInfo += {
		## The entity body excerpt.
		excerpt:    string &log &default="";
	};
	
	## This is the default value for how much of the entity body should be
	## included for all MIME entities.
	const default_entity_excerpt_len = 0 &redef;
}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, f: fa_file)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_NEW ) return;
	if ( ! f?$source ) return;
	if ( f$source != "SMTP" ) return;

	if ( default_entity_excerpt_len > f$bof_buffer_size )
		f$bof_buffer_size = default_entity_excerpt_len;
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, f: fa_file)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_BOF_BUFFER ) return;
	if ( ! f?$bof_buffer ) return;
	if ( ! f?$source ) return;
	if ( f$source != "SMTP" ) return;
	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( ! c?$smtp ) next;

		if ( default_entity_excerpt_len > 0 )
			c$smtp$current_entity$excerpt =
			        f$bof_buffer[0:default_entity_excerpt_len];
		}
	}
