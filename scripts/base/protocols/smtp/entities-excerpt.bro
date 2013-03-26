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

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_NEW ) return;
	if ( ! info?$source ) return;
	if ( info$source != "SMTP" ) return;

	if ( default_entity_excerpt_len > info$bof_buffer_size )
		info$bof_buffer_size = default_entity_excerpt_len;
	}

hook FileAnalysis::policy(trig: FileAnalysis::Trigger, info: FileAnalysis::Info)
	&priority=5
	{
	if ( trig != FileAnalysis::TRIGGER_BOF_BUFFER ) return;
	if ( ! info?$bof_buffer ) return;
	if ( ! info?$source ) return;
	if ( info$source != "SMTP" ) return;
	if ( ! info?$conns ) return;

	for ( cid in info$conns )
		{
		local c: connection = info$conns[cid];

		if ( ! c?$smtp ) next;

		if ( default_entity_excerpt_len > 0 )
			c$smtp$current_entity$excerpt =
			        info$bof_buffer[0:default_entity_excerpt_len];
		}
	}
